"""Reset the admin password from the server:  sudo docker compose exec panel python3 reset_admin.py"""
import json, secrets
from werkzeug.security import generate_password_hash
P = "/data/panel/settings.json"
s = json.load(open(P))
pw = secrets.token_urlsafe(12)
s["admin"]["hash"] = generate_password_hash(pw)
json.dump(s, open(P, "w"), indent=2)
print(f"Admin user: {s['admin']['user']}\nNew password: {pw}\nSign in and change it under Settings.")
