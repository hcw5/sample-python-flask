import os
from flask import Flask
from flask import render_template, session, request, redirect, url_for, flash, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import secrets
import json, base64, time
from functools import wraps

app = Flask(__name__)
jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = '#^\x04<\x90\tH^\x83\x05\xa2\x88\xfe8s\xad\x9e_\xd6\x82I\xed\xe4\xdf\xb9\x92\x80\xcc\x8d:\xf0\xe7\xb3|\x16Ssy\xd4\x01\x0b"\x0e;nc\xb1\xbb\xd0\xe1\xd0\\@\x11e\xa3\xbb\xb3\x1b\x83\x99\xde\x8d}'
app.secret_key = secrets.token_bytes(128)
app.permanent_session_lifetime = datetime.timedelta(minutes=90)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

def get_ip():
	headers = [
		'CF-Connecting-IP',   # Cloudflare
		'True-Client-IP',     # Akamai
		'X-Real-IP',          # Nginx proxy/Fastly
		'X-Forwarded-For',    # Most proxies
		'X-Cluster-Client-IP' # Rackspace Cloud Load Balancer, Riverbed's Stingray
	]
	for header in headers:
		if request.headers.get(header):
			return request.headers[header].split(',')[0].strip()
	return request.remote_addr

def rate_limit(max_per_minute):
	interval = 60.0 / float(max_per_minute)
	def decorator(f):
		times = {}
		@wraps(f)
		def wrapped_f(*args, **kwargs):
			ip = get_ip()
			now = time.time()
			if ip not in times:
				times[ip] = [now]
			else:
				while times[ip] and now - times[ip][-1] > interval:
					times[ip].pop()
				times[ip].append(now)
				if len(times[ip]) > max_per_minute:
					return jsonify({"message": "Too many requests"}), 429
			return f(*args, **kwargs)
		return wrapped_f
	return decorator


def authenticate(username, password):
    if username == 'hassan' and password == 'hussin':
        id = secrets.token_urlsafe(128)
        return True, id
    else:
        return False, None





@app.route("/api/login", methods=['POST'])
@rate_limit(5)
def login():
    data = request.get_json()  # Get data as JSON
    username = data['username']
    password = data['password']
    password = base64.b64decode(password).decode('utf-8')
    is_authenticated, id = authenticate(username, password)
    if is_authenticated:
        access_tok = create_access_token(identity=username)
        return jsonify(access_token=access_tok), 200
    else:
        return {'message': 'invalid credentials'}, 401  # Return a JSON response with a 401 Unauthorized status

    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/home")
def hello():
    return render_template('home.html')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
