"""Read-only Intune device details from Microsoft Graph.

Uses an Entra app registration (client credentials) with the application permission
DeviceManagementManagedDevices.Read.All. The device list is cached on disk and
refreshed every 15 minutes in the background, so pages never wait on Graph.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# Overridable only for automated tests against a mock server.
LOGIN_URL = os.environ.get("INTUNE_LOGIN_URL", "https://login.microsoftonline.com")
GRAPH_URL = os.environ.get("INTUNE_GRAPH_URL", "https://graph.microsoft.com")
FIELDS = ("id,deviceName,userPrincipalName,userDisplayName,manufacturer,model,serialNumber,"
          "operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime")
REFRESH_SECS = 15 * 60


class IntuneError(Exception):
    pass


def _graph_error(e):
    try:
        body = json.loads(e.read().decode())
        err = body.get("error")
        if isinstance(err, dict):
            return f"{err.get('code', e.code)}: {err.get('message', '')}"
        return f"{err}: {body.get('error_description', '').splitlines()[0]}"
    except Exception:
        return f"HTTP {e.code}"


def fetch_devices(tenant, client_id, secret):
    """All Intune managed devices (list of dicts). Raises IntuneError with a readable message."""
    data = urllib.parse.urlencode({"client_id": client_id, "client_secret": secret,
                                   "grant_type": "client_credentials",
                                   "scope": "https://graph.microsoft.com/.default"}).encode()
    try:
        with urllib.request.urlopen(f"{LOGIN_URL}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token",
                                    data=data, timeout=20) as r:
            token = json.load(r)["access_token"]
        url = f"{GRAPH_URL}/v1.0/deviceManagement/managedDevices?$select={FIELDS}&$top=999"
        devices = []
        while url:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=30) as r:
                page = json.load(r)
            devices += page.get("value", [])
            url = page.get("@odata.nextLink")
        return devices
    except urllib.error.HTTPError as e:
        raise IntuneError(_graph_error(e)) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise IntuneError(f"Cannot reach Microsoft: {getattr(e, 'reason', e)}") from None
    except (KeyError, ValueError):
        raise IntuneError("Unexpected answer from Microsoft") from None


class IntuneCache:
    def __init__(self, path, get_config):
        self.path = path
        self.get_config = get_config  # -> {"tenant_id", "client_id", "client_secret"} or None
        self.lock = threading.Lock()
        self._mem = None

    def state(self):
        if self._mem is None:
            try:
                with open(self.path) as f:
                    self._mem = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self._mem = {"devices": {}, "updated": 0, "error": "", "count": 0}
        return self._mem

    def enabled(self):
        return bool(self.get_config())

    def lookup(self, name):
        if not name or not self.enabled():
            return None
        return self.state()["devices"].get(name.lower())

    def refresh(self):
        cfg = self.get_config()
        if not cfg:
            return False
        with self.lock:
            st = dict(self.state())
            try:
                devices = fetch_devices(cfg["tenant_id"], cfg["client_id"], cfg["client_secret"])
                by_name = {}
                for d in devices:
                    key = (d.get("deviceName") or "").lower()
                    if not key:
                        continue
                    old = by_name.get(key)  # re-enrolled devices: keep the most recently synced
                    if old is None or (d.get("lastSyncDateTime") or "") > (old.get("lastSyncDateTime") or ""):
                        by_name[key] = d
                st.update(devices=by_name, count=len(by_name), updated=int(time.time()), error="")
                ok = True
            except IntuneError as e:
                st.update(error=str(e), error_at=int(time.time()))
                ok = False
            tmp = f"{self.path}.tmp"
            with open(tmp, "w") as f:
                json.dump(st, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            self._mem = st
            return ok

    def start(self):
        def loop():
            while True:
                try:
                    st = self.state()
                    last = max(st.get("updated", 0), st.get("error_at", 0))
                    if self.enabled() and time.time() - last > REFRESH_SECS:
                        self.refresh()
                except Exception as e:  # never let the background thread die
                    print(f"intune refresh: {e}", flush=True)
                time.sleep(60)
        threading.Thread(target=loop, daemon=True, name="intune-refresh").start()
