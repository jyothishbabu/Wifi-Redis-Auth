# Certificate-based Wi-Fi (EAP-TLS) with a web admin panel

```
Intune laptop ── SSID ──► Aruba AP / Virtual Controller ──(UDP 1812, office public IP)──► AWS EC2
 (device cert from                                                                        ├─ FreeRADIUS (EAP-TLS only)
  Intune Cloud PKI)                                                                       └─ Admin panel  https://<ip>:8443
```

Laptops join only with a certificate from Intune Cloud PKI. Passwords and MAC filtering aren't used.
**Everything is configured in the admin panel.** There is no `.env` and no config file to edit.

## Deploy (EC2)

1. **AWS:** Amazon Linux 2023, t3.small, Elastic IP, IAM role with `AmazonSSMManagedInstanceCore`.
   Security Group inbound from **each office public IP /32 only**: UDP 1812, UDP 1813, TCP 8443. No port 22.
2. **On the server** (Session Manager):
   ```bash
   sudo dnf install -y docker git && sudo systemctl enable --now docker
   sudo mkdir -p /usr/local/lib/docker/cli-plugins && cd /usr/local/lib/docker/cli-plugins
   sudo curl -sSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o docker-compose
   V=$(curl -s https://api.github.com/repos/docker/buildx/releases/latest | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
   sudo curl -sSL https://github.com/docker/buildx/releases/download/$V/buildx-$V.linux-amd64 -o docker-buildx
   sudo chmod +x docker-compose docker-buildx
   sudo git clone <this repo> /opt/wifi-radius && cd /opt/wifi-radius
   sudo docker compose up -d --build
   sudo docker compose logs panel | grep "SETUP CODE"
   ```
3. From an office, open **https://&lt;Elastic-IP&gt;:8443**. Accept the one-time certificate warning, enter the setup code, then fill in the SSID, admin account and first office.

## Then, in the panel

| Page | What to do |
|---|---|
| **Certificates** | Upload the Intune Cloud PKI **root and issuing CA** (Intune → Tenant administration → Cloud PKI → each CA → Download). **Download RADIUS-Root-CA.cer** for Intune. |
| **Offices** | Add each office's public IP. Each gets its own generated secret. **Aruba config** shows the ready-to-paste CLI for that office. |
| **Dashboard** | The setup checklist shows what is left. Also: status, logins in the last 24h, certificate expiry. |
| **Logins / Devices** | Who connected or was rejected and why. Block or unblock a laptop with one click. |
| **Settings** | SSID, admin username and password, extra admin IPs, verbose RADIUS logging. |
| **Logs & config** | RADIUS log, generated config, and an audit log of every admin action. |

Every change is checked with `radiusd -C` before it goes live. If the check fails, the running config stays and the error shows on the dashboard.

## Intune profiles (assign all four to one device group)

1. **Trusted certificate:** `RADIUS-Root-CA.cer` (from the Certificates page)
2. **Trusted certificate:** the Cloud PKI root
3. **SCEP certificate:**
   - Device type, subject `CN={{DeviceName}}`, SAN DNS `{{DeviceName}}`
   - TPM, RSA 2048, EKU Client Authentication
   - Root = profile 2, URL = the Cloud PKI SCEP URI
4. **Wi-Fi (Enterprise):**
   - Your SSID, EAP-TLS
   - Server name = the RADIUS server name on the Certificates page
   - Server root = profile 1, client certificate = profile 3
   - Machine authentication

## Security

| Layer | What it stops |
|---|---|
| Security Group: office IPs only | Everyone else never reaches the server |
| Per-office RADIUS clients and secrets, Message-Authenticator required | Forged or foreign RADIUS requests (BlastRADIUS) |
| EAP-TLS only, laptop certificate must chain to the uploaded CAs | Personal devices, stolen passwords, rogue certificates |
| Laptop checks the RADIUS server certificate and name | Fake access points |
| Block list | Lost or stolen laptops |
| Panel: HTTPS, its own office-IP check, hashed password, lockout after 5 failures, setup code, lockout guard | Panel takeover |

## Operations

| Task | How |
|---|---|
| Back up | Copy `/opt/wifi-radius/data/panel/`. It holds all settings, keys and the block list |
| Update the code | `cd /opt/wifi-radius && sudo git pull && sudo docker compose up -d --build` |
| Office IP changed | Update the Security Group **first**, then the Offices page |
| Forgot the admin password | `cd /opt/wifi-radius && sudo docker compose exec panel python3 reset_admin.py` prints a new one |
