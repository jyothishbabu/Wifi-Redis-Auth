"""Read-only device inventory from Intune (Microsoft Graph) and Jamf Pro.

Each source is fetched in the background every 15 minutes, normalised to one shape
and cached on disk, so pages never wait on the MDM:
  {source, name, user, upn, model, serial, os, compliance, last_sync}
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

REFRESH_SECS = 15 * 60
# Overridable only for automated tests against a mock server.
INTUNE_LOGIN_URL = os.environ.get("INTUNE_LOGIN_URL", "https://login.microsoftonline.com")
INTUNE_GRAPH_URL = os.environ.get("INTUNE_GRAPH_URL", "https://graph.microsoft.com")


class MdmError(Exception):
    pass


def _http_error(e):
    try:
        body = json.loads(e.read().decode())
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            return f"{err.get('code', e.code)}: {err.get('message', '')}"
        if err:
            return f"{err}: {str(body.get('error_description', '')).splitlines()[0]}"
        if isinstance(body, dict) and body.get("errors"):
            return f"HTTP {e.code}: {body['errors'][0].get('description', '')}"
    except Exception:
        pass
    return f"HTTP {e.code}"


def _call(fn):
    try:
        return fn()
    except urllib.error.HTTPError as e:
        raise MdmError(_http_error(e)) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise MdmError(f"Cannot reach the server: {getattr(e, 'reason', e)}") from None
    except (KeyError, ValueError, TypeError):
        raise MdmError("Unexpected answer from the server") from None


def _token(url, form):
    data = urllib.parse.urlencode(form).encode()
    with urllib.request.urlopen(url, data=data, timeout=20) as r:
        return json.load(r)["access_token"]


def _get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


# ---------------------------------------------------------------- Intune
INTUNE_FIELDS = ("id,deviceName,userPrincipalName,userDisplayName,manufacturer,model,serialNumber,"
                 "operatingSystem,osVersion,complianceState,lastSyncDateTime,azureADDeviceId")


def fetch_intune(cfg):
    """[(record, [lookup keys])] from Intune managed devices."""
    def run():
        token = _token(f"{INTUNE_LOGIN_URL}/{urllib.parse.quote(cfg['tenant_id'])}/oauth2/v2.0/token",
                       {"client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
                        "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
        url = f"{INTUNE_GRAPH_URL}/v1.0/deviceManagement/managedDevices?$select={INTUNE_FIELDS}&$top=999"
        out = []
        while url:
            page = _get(url, token)
            out += page.get("value", [])
            url = page.get("@odata.nextLink")
        return out
    out = []
    for d in _call(run):
        rec = {"source": "Intune", "name": d.get("deviceName") or "",
               "user": d.get("userDisplayName") or d.get("userPrincipalName") or "",
               "upn": d.get("userPrincipalName") or "",
               "model": f"{d.get('manufacturer') or ''} {d.get('model') or ''}".strip(),
               "serial": d.get("serialNumber") or "",
               "os": f"{d.get('operatingSystem') or ''} {d.get('osVersion') or ''}".strip(),
               "compliance": d.get("complianceState") or "", "last_sync": d.get("lastSyncDateTime") or ""}
        # Certificates may carry the name, the Entra device ID or the Intune device ID.
        out.append((rec, [d.get("deviceName"), d.get("id"), d.get("azureADDeviceId")]))
    return out


# ---------------------------------------------------------------- Jamf Pro
def fetch_jamf(cfg):
    """[(record, [lookup keys])] from Jamf Pro computer inventory (API client, Read Computers)."""
    base = cfg["url"].rstrip("/")

    def run():
        token = _token(f"{base}/api/oauth/token", {"client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
                                                   "grant_type": "client_credentials"})
        out, page = [], 0
        while True:
            q = ("section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&section=OPERATING_SYSTEM"
                 f"&page={page}&page-size=200")
            data = _get(f"{base}/api/v1/computers-inventory?{q}", token)
            res = data.get("results", [])
            out += res
            page += 1
            if not res or len(out) >= data.get("totalCount", 0):
                return out
    out = []
    for c in _call(run):
        g, h = c.get("general") or {}, c.get("hardware") or {}
        u, o = c.get("userAndLocation") or {}, c.get("operatingSystem") or {}
        managed = (g.get("remoteManagement") or {}).get("managed")
        rec = {"source": "Jamf", "name": g.get("name") or "",
               "user": u.get("realname") or u.get("username") or "",
               "upn": u.get("email") or u.get("username") or "",
               "model": h.get("model") or "", "serial": h.get("serialNumber") or "",
               "os": f"macOS {o.get('version')}" if o.get("version") else "",
               "compliance": "managed" if managed else ("unmanaged" if managed is False else ""),
               "last_sync": g.get("lastContactTime") or ""}
        # Jamf SCEP certificates usually carry the serial number ($SERIALNUMBER) or the name.
        out.append((rec, [g.get("name"), h.get("serialNumber"), h.get("udid") or c.get("udid")]))
    return out


# ---------------------------------------------------------------- cache
class MdmCache:
    def __init__(self, path, get_config, fetch):
        self.path, self.get_config, self.fetch = path, get_config, fetch
        self.lock = threading.Lock()
        self._mem = None

    def state(self):
        if self._mem is None:
            try:
                with open(self.path) as f:
                    self._mem = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self._mem = {"index": {}, "updated": 0, "error": "", "count": 0}
        return self._mem

    def enabled(self):
        return bool(self.get_config())

    def lookup(self, key):
        if not key or not self.enabled():
            return None
        return self.state()["index"].get(key.lower().removeprefix("host/"))

    def refresh(self):
        cfg = self.get_config()
        if not cfg:
            return False
        with self.lock:
            st = dict(self.state())
            try:
                index, names = {}, set()
                for rec, keys in self.fetch(cfg):
                    if rec["name"]:
                        names.add(rec["name"].lower())
                    for k in keys:
                        if not k or k == "00000000-0000-0000-0000-000000000000":
                            continue
                        old = index.get(k.lower())  # duplicates: keep the most recently seen
                        if old is None or rec["last_sync"] > old["last_sync"]:
                            index[k.lower()] = rec
                st.update(index=index, count=len(names), updated=int(time.time()), error="")
                ok = True
            except MdmError as e:
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
                    if self.enabled() and time.time() - max(st.get("updated", 0), st.get("error_at", 0)) > REFRESH_SECS:
                        self.refresh()
                except Exception as e:  # never let the background thread die
                    print(f"mdm refresh: {e}", flush=True)
                time.sleep(60)
        threading.Thread(target=loop, daemon=True).start()
