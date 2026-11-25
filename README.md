# WiFi Redis Authenticator

Certificate-only Wi-Fi (WPA2-Enterprise, EAP-TLS) for Aruba access points, with a web admin panel.
Laptops join with their own certificate, with no password and no MAC filtering. Everything is configured in the panel.

```
Laptop (certificate) ── SSID ──► Aruba AP / Virtual Controller ──UDP 1812──► AWS EC2 (Docker)
                                                                             ├─ redis: FreeRADIUS, EAP-TLS only
                                                                             └─ panel: https://<Elastic-IP>:8443
```

| Part | What it does |
|---|---|
| `redis` container | FreeRADIUS. It answers only the office IPs and accepts only laptop certificates from trusted CAs that aren't on the block list |
| `panel` container | Admin web app. Setup, offices, laptops and certificates, Intune details, logins, block list, logs |
| `data/` on the server | All settings, keys, certificates and logs. **Back this folder up** |

---

## 1. Deploy (once)

**AWS**
- **EC2:** Amazon Linux 2023, t4g.small (ARM) or t3.small (x86), 20 GB.
- **IAM role:** `AmazonSSMManagedInstanceCore`. Connect with Session Manager; no SSH and no port 22.
- **Elastic IP:** associate one with the instance.
- **Security Group inbound:** from **every office public IP /32** only:

  | Port | Purpose |
  |---|---|
  | UDP 1812 | Wi-Fi logins |
  | UDP 1813 | Accounting |
  | TCP 8443 | Admin panel |

**Server** (Session Manager)
```bash
sudo dnf install -y docker git && sudo systemctl enable --now docker
sudo mkdir -p /usr/local/lib/docker/cli-plugins && cd /usr/local/lib/docker/cli-plugins
A=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')
sudo curl -sSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m) -o docker-compose
V=$(curl -s https://api.github.com/repos/docker/buildx/releases/latest | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
sudo curl -sSL https://github.com/docker/buildx/releases/download/$V/buildx-$V.linux-$A -o docker-buildx
sudo chmod +x docker-compose docker-buildx

# Private repo: add a read-only deploy key first (GitHub → repo → Settings → Deploy keys)
sudo git clone git@github.com:jyothishbabu/Wifi-Redis-Auth.git /opt/wifi-redis && cd /opt/wifi-redis
sudo docker compose up -d --build
sudo docker compose logs panel | grep "SETUP CODE"
```

## 2. First-time setup (panel)

From an office, open **https://&lt;Elastic-IP&gt;:8443**. The certificate warning appears only this once. Enter the setup code, then:
- **SSID name**, exactly as on Aruba (it's case-sensitive)
- **Admin username and password**
- **First office:** its name and public IPs (comma-separated if there are several)
- **Redis server name:** keep the default. Laptops check it; it needs no DNS
- **Panel address:** the Elastic IP

The panel restarts with its own certificate. Then follow the **Dashboard → Setup checklist**.

## 3. Aruba (each office)

Panel → **Offices** → add all offices and **all** their public IPs → **Aruba config** gives you ready-to-paste CLI.
Check these three lines on the virtual controller:

| Setting | Must be | If it's wrong |
|---|---|---|
| `wlan auth-server … ip` | The **Elastic IP**, not a hostname | "Authentication server is unresponsive" |
| `wlan auth-server … key` | The office secret from the panel | "Unresponsive" (the server silently drops the request) |
| `wlan ssid-profile … opmode` | `wpa2-aes`, not `wpa-aes` | Windows: "The specific network is not available" |

## 4. Put certificates on laptops (three ways)

**A. Intune: automatic for every managed laptop** (needs the Intune Suite or Cloud PKI licence)
1. Intune → Tenant administration → **Cloud PKI**: create a Root CA, then an Issuing CA, both with EKU **Client Authentication**. Download both `.cer` files and copy the Issuing CA's **SCEP URI**.
2. Panel → **Certificates**: upload both `.cer` files, and download **Redis-Root-CA.cer**.
3. Intune → Devices → Windows → Configuration. Create these profiles and assign all of them to one **device** group:

   | Profile | Key settings |
   |---|---|
   | Trusted certificate | `Redis-Root-CA.cer` → Computer store **Root** |
   | Trusted certificate | Cloud PKI root → Computer store **Root** |
   | Trusted certificate | Cloud PKI issuing → Computer store **Intermediate** |
   | SCEP certificate | **Device** · `CN={{DeviceName}}` (`{{AAD_Device_ID}}` also works) · TPM KSP if present · EKU Client Authentication · Root = the Cloud PKI root profile · URL = the SCEP URI |
   | Wi-Fi (Enterprise) | Your SSID · WPA/WPA2-Enterprise · **Machine** · EAP-TLS · Server name = the panel's server name · Server root = `Redis-Root-CA.cer` · Client certificate = the SCEP profile |

4. Pilot 2–3 laptops: all 5 profiles **Succeeded**, then **ACCEPT** on the panel's Logins page. Then add everyone.

**B. Jamf Pro: automatic for every managed Mac**
1. Panel → **Jamf** → **Turn on automatic certificates**. The page shows the SCEP URL, the challenge and the CA fingerprint.
2. Jamf Pro → Computers → **Configuration Profiles** → New. Level **Computer**, Install Automatically. Add three payloads:

   | Payload | Key settings |
   |---|---|
   | Certificate | Upload `Redis-Root-CA.cer` |
   | SCEP | URL from the panel · Subject `CN=$SERIALNUMBER` · Static challenge from the panel · Key size 2048 · digital signature + key encipherment · fingerprint from the panel |
   | Network | Wi-Fi · your SSID · Auto Join · WPA2 Enterprise · EAP **TLS** · Identity = the SCEP payload · Trust `Redis Root CA` · server name from the panel |

3. Scope it to 2–3 pilot Macs, then to everyone. Each Mac creates its own key, gets its certificate from the panel and joins automatically. It must be on an office network (or a VPN leaving from an office IP) when the profile installs.
4. Optional: Panel → Jamf → **Jamf Pro inventory** (API client with *Read Computers*). Macs then show their Jamf name, user, model and managed state instead of a serial number.

**C. Panel: for laptops not in Intune or Jamf** (Windows or Mac)
Panel → **Devices → Add laptop**, then either:
- Send the **one-time install link**. It works once, lasts 7 days, and opens only from office IPs. Or:
- Download the **installer** yourself.

| Windows | Mac / iPhone |
|---|---|
| Open `Install-WiFi-<name>.cmd` → **Yes** on the admin prompt → Done | Open `WiFi-<name>.mobileconfig` → System Settings → Device Management → **Install** |

Each installer adds the root, the laptop's own certificate (valid 1 year) and the Wi-Fi network. Nothing to type.

**Optional:** Settings → **Intune** (read-only Microsoft Graph) shows each laptop's user, model, serial, OS and compliance, and flags laptops that are non-compliant or not in Intune.

## 5. Go-live checklist

- [ ] Dashboard: every **Setup checklist** item is done, and the status shows **Redis running**
- [ ] Every office and **all** its public IPs are on the Offices page **and** in the Security Group
- [ ] Each office's Aruba: Elastic IP, current key, `opmode wpa2-aes`
- [ ] Office secrets rotated (Offices → Generate → Save, then re-paste on Aruba) if one was ever shared
- [ ] Pilot laptops show **ACCEPT** on Logins (Intune and/or installer)
- [ ] **No TEST CA** under Certificates → Trusted laptop CAs
- [ ] Jamf profile scoped and pilot Macs show ACCEPT (if you use Jamf)
- [ ] Intune / Jamf inventory connected (optional), with reminders before their client secrets expire
- [ ] `data/` backed up, and the GitHub repo is **private**
- [ ] Admin password stored in your password manager

## 6. Daily operations

| Task | How |
|---|---|
| New laptop | Intune or Jamf: nothing to do. Otherwise: Devices → Add laptop |
| Lost, stolen or leaving | Devices → **Block** or **Remove**. Takes effect in seconds. Also retire or wipe it in Intune |
| Who connected | **Logins** (filter, export CSV). Rejected attempts show the reason |
| Office IP changed | Security Group **first**, then Offices |
| Troubleshoot one laptop | Settings → Verbose logging → Logs & config → Redis server log. Turn it off afterwards |
| Update the software | `cd /opt/wifi-redis && sudo git pull && sudo docker compose up -d --build --remove-orphans` |
| Forgot the admin password | `cd /opt/wifi-redis && sudo docker compose exec panel python3 reset_admin.py` |
| Back up | `sudo tar czf wifi-backup-$(date +%F).tgz -C /opt/wifi-redis data`. Store it encrypted; it contains private keys |
| Restore on a new server | Deploy (step 1), stop the stack, put `data/` back, `sudo docker compose up -d`. Laptops keep working, because the same CAs and keys come back |

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Windows asks for a username and password | No Wi-Fi profile on the laptop, or the SSID name or security doesn't match | Install the profile (Intune or installer). Check the SSID spelling and `opmode wpa2-aes` |
| "The specific network is not available" | Aruba broadcasts WPA, the profile expects WPA2 | Aruba `opmode wpa2-aes` |
| "Authentication server is unresponsive" | Requests don't reach Redis, or are ignored | Aruba `ip` = Elastic IP; key matches; office IP on the Offices page and in the Security Group. On the server: `sudo tcpdump -ni any udp port 1812` |
| Logins: REJECT `unable to get local issuer` / `unknown CA` | The laptop's certificate CA isn't trusted | Certificates → upload the Cloud PKI root **and** issuing CA |
| Logins: REJECT `TLS Alert … unknown CA` | The **laptop** doesn't trust the server | Intune Wi-Fi profile: server name and `Redis-Root-CA.cer` must match the panel |
| Logins: REJECT `is blocked` | The laptop is on the block list | Devices → Unblock |
| Dashboard: Redis **waiting** | No trusted laptop CA yet, or a config error | Add a laptop or upload the Intune CAs. The error is shown under the status bar |
| Device shows as a GUID or serial number | The certificate carries a device ID or serial | Connect Intune (Settings) or Jamf inventory (Jamf page). The panel then shows the real name |
| Jamf profile fails to install on a Mac | The Mac wasn't on an office network, or the challenge changed | Bring it to the office and use **Redistribute**; after a new challenge, update the SCEP payload |

## 8. Security

| Layer | What it stops |
|---|---|
| Security Group: office IPs only | Everyone else never reaches the server |
| Per-office clients and secrets, Message-Authenticator required | Forged or foreign requests (BlastRADIUS) |
| EAP-TLS only; certificate must chain to a trusted CA and not be blocked | Personal devices, stolen passwords, rogue certificates |
| Laptop pins the server name and root | Fake access points |
| Panel: HTTPS, its own office-IP check, hashed password, login lockout, setup code, lockout guard, audit log | Panel takeover |
| Laptop private keys are never stored on the server; Intune keys stay in the TPM | Key theft from the server |

## 9. Upgrading an install from before the Redis rename

Earlier installs live in `/opt/wifi-radius` and use the old repository name. To move one (Wi-Fi stops for about a minute):
```bash
cd /opt/wifi-radius && sudo docker compose down
cd /opt && sudo mv wifi-radius wifi-redis && cd /opt/wifi-redis
sudo git remote set-url origin git@github.com:jyothishbabu/Wifi-Redis-Auth.git
sudo git pull
sudo docker compose up -d --build --remove-orphans
sudo docker compose ps          # wifi-redis + wifi-redis-panel running
```
All settings, laptops and certificates are kept in `data/`, which moves with the folder. The GitHub deploy key keeps working after a repository rename.
