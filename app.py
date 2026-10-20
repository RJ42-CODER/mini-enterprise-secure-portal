from flask import Flask, request, render_template_string
import os
import sys

# Load environment variables from .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure we can import security_agent
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from security_agent.config import load_portal_env, validate_portal_config, get_client_ip
from security_agent.detector import ServerDetector

# Load environment settings from project .env
load_portal_env()

# Perform startup configuration validation for all required parameters
config = validate_portal_config()
cn_server_ip = config["CN_SERVER_IP"]
soc_url = config["SOC_URL"]
server_port = config["PORT"]
flask_host = config["FLASK_HOST"]

print("[CONFIG] Security Portal initializing with validated parameters:")
print(f"  CN_SERVER_IP = {cn_server_ip}")
print(f"  SOC_URL      = {soc_url}")
print(f"  PORT         = {server_port}")
print(f"  FLASK_HOST   = {flask_host}")
print("  SOC AUTH     = [CONFIGURED]")

app = Flask(__name__)

detector = ServerDetector(port=server_port)
app.config['MAX_CONTENT_LENGTH'] = detector.waf.config.max_content_length

@app.before_request
def before_request():
    form_body = ""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            form_body = "&".join(f"{k}={v}" for k, v in request.form.items())
        except Exception:
            pass

    client_ip = get_client_ip(request)
    event = detector.inspect_http_request(
        source_ip=client_ip,
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        query_string=request.query_string.decode('utf-8', errors='ignore'),
        body=form_body,
        content_length=request.content_length
    )

    if isinstance(event, dict) and event.get("_waf_blocked") and event.get("_waf_detection"):
        return detector.waf.build_client_response(event["_waf_detection"])

@app.errorhandler(413)
def request_entity_too_large(error):
    client_ip = get_client_ip(request)
    detector._trigger_event(
        event_type="REQUEST_SIZE_LIMIT",
        signature="DIR_FUZZ",
        severity="MEDIUM",
        source_ip=client_ip,
        destination_port=server_port,
        message=f"Request body exceeded maximum content length limit ({detector.waf.config.max_content_length} bytes)",
        metadata={"size": request.content_length or 0, "max_allowed": detector.waf.config.max_content_length}
    )
    return detector.waf.build_client_response({
        "status_code": 413,
        "rule": "REQUEST_SIZE_LIMIT",
        "client_message": "413 Payload Too Large: Request body exceeds the maximum permitted size."
    })

@app.errorhandler(405)
def method_not_allowed(error):
    return detector.waf.build_client_response({
        "status_code":405,
        "rule":"DISALLOWED_METHOD",
        "client_message":"405 Method Not Allowed"
    })

@app.errorhandler(404)
def not_found(error):
    client_ip = get_client_ip(request)
    detector.record_not_found(
        source_ip=client_ip,
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        status_code=404
    )
    return "404 Not Found: The requested resource was not found on this server.", 404


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Enterprise Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #111827;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .login-box {
            background: #1f2937;
            padding: 35px;
            border-radius: 12px;
            width: 350px;
        }

        h1 {
            text-align: center;
        }

        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
        }

        button {
            width: 100%;
            padding: 12px;
            background: #2563eb;
            color: white;
            border: none;
            cursor: pointer;
            margin-top: 10px;
        }

        .status {
            margin-top: 15px;
            text-align: center;
        }
    </style>
</head>

<body>

<div class="login-box">

    <h1>Secure Portal</h1>

    <form method="POST">

        <input
            type="text"
            name="username"
            placeholder="Username"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <button type="submit">LOGIN</button>

    </form>

    {% if message %}
        <div class="status">
            {{ message }}
        </div>
    {% endif %}

</div>

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        expected_password = os.getenv("PORTAL_ADMIN_PASSWORD", "admin123")

        client_ip = get_client_ip(request)
        if username == "admin" and password == expected_password:
            message = "Login successful"
            detector.record_auth_success(
                source_ip=client_ip,
                username=username or ""
            )
        else:
            message = "Invalid username or password"
            detector.record_auth_failure(
                source_ip=client_ip,
                username=username or ""
            )

    return render_template_string(HTML, message=message)


if __name__ == "__main__":
    app_host = os.getenv("FLASK_HOST", "127.0.0.1")
    app.run(host=app_host, port=server_port)
