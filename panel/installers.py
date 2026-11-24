"""One-file Wi-Fi installers for a laptop: its certificate, the Redis root CA and an
EAP-TLS Wi-Fi profile, bundled so the user installs everything in one step.

- Windows: a .cmd file. Double-click, approve the admin prompt, done.
  Installs machine-wide (like Intune): root -> LocalMachine\\Root, certificate ->
  LocalMachine\\My, Wi-Fi profile for all users with machine authentication.
- macOS / iOS: a .mobileconfig configuration profile.
"""
import base64
import hashlib
import plistlib
import uuid
from xml.sax.saxutils import escape


def wlan_profile_xml(ssid, server_name, root_der):
    """Windows WLAN profile: WPA2-Enterprise, EAP-TLS, machine auth, server name + root pinned."""
    thumb = " ".join(f"{b:02x}" for b in hashlib.sha1(root_der).digest())
    ssid_x, server_x = escape(ssid), escape(server_name)
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid_x}</name>
  <SSIDConfig><SSID><name>{ssid_x}</name></SSID><nonBroadcast>false</nonBroadcast></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2</authentication>
        <encryption>AES</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>machine</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
              <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                <Type>13</Type>
                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                  <CredentialsSource>
                    <CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore>
                  </CredentialsSource>
                  <ServerValidation>
                    <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                    <ServerNames>{server_x}</ServerNames>
                    <TrustedRootCA>{thumb}</TrustedRootCA>
                  </ServerValidation>
                  <DifferentUsername>false</DifferentUsername>
                  <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
                  <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
                </EapType>
              </Eap>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"""


PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$ssid = '__SSID__'
$device = '__DEVICE__'
try {
  Write-Host ""
  Write-Host "Setting up Wi-Fi '$ssid' for $device ..." -ForegroundColor Cyan
  $tmp = Join-Path $env:TEMP ('wifi-setup-' + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  [IO.File]::WriteAllBytes("$tmp\root.cer", [Convert]::FromBase64String('__ROOT__'))
  [IO.File]::WriteAllBytes("$tmp\device.pfx", [Convert]::FromBase64String('__PFX__'))
  [IO.File]::WriteAllBytes("$tmp\wifi.xml", [Convert]::FromBase64String('__XML__'))

  Write-Host " [1/3] Trusting the Wi-Fi server certificate"
  Import-Certificate -FilePath "$tmp\root.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

  Write-Host " [2/3] Installing this laptop's certificate"
  $pw = ConvertTo-SecureString '__PW__' -AsPlainText -Force
  Import-PfxCertificate -FilePath "$tmp\device.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $pw | Out-Null

  Write-Host " [3/3] Adding the Wi-Fi network"
  netsh wlan delete profile name="$ssid" 2>&1 | Out-Null
  $out = netsh wlan add profile filename="$tmp\wifi.xml" user=all
  if ($LASTEXITCODE -ne 0) { throw "netsh: $out" }

  Remove-Item -Recurse -Force $tmp
  netsh wlan connect name="$ssid" 2>&1 | Out-Null
  Write-Host ""
  Write-Host "Done. This laptop now joins '$ssid' automatically, with no password." -ForegroundColor Green
  Write-Host "You can delete this installer file."
} catch {
  if ($tmp -and (Test-Path $tmp)) { Remove-Item -Recurse -Force $tmp }
  Write-Host ""
  Write-Host "Setup failed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "Send this message to IT."
}
"""

CMD_HEAD = r"""@echo off
rem Wi-Fi setup for __DEVICE__ (__SSID__). Double-click to run; approve the admin prompt.
rem This file contains this laptop's Wi-Fi certificate. Delete it after use; don't share it.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t = Get-Content -LiteralPath '%~f0' -Raw; $c = ($t -split ('#POWER' + 'SHELL-BELOW'))[1]; Invoke-Expression $c"
echo.
pause
exit /b
#POWERSHELL-BELOW
"""


def windows_installer(device, ssid, server_name, root_der, pfx, pfx_password):
    xml = wlan_profile_xml(ssid, server_name, root_der)
    b64 = lambda b: base64.b64encode(b).decode()
    ps = (PS_TEMPLATE.replace("__SSID__", ssid).replace("__DEVICE__", device)
          .replace("__ROOT__", b64(root_der)).replace("__PFX__", b64(pfx))
          .replace("__XML__", b64(xml.encode())).replace("__PW__", pfx_password))
    head = CMD_HEAD.replace("__DEVICE__", device).replace("__SSID__", ssid)
    return (head + ps).replace("\r\n", "\n").replace("\n", "\r\n").encode()


def mac_profile(device, ssid, server_name, root_der, pfx, pfx_password):
    """Apple configuration profile: Redis root + device identity + EAP-TLS Wi-Fi network."""
    ids = {k: str(uuid.uuid4()).upper() for k in ("top", "root", "id", "wifi")}
    base = "local.wifi-redis"

    def payload(kind, ptype, name, **extra):
        return {"PayloadType": ptype, "PayloadVersion": 1, "PayloadUUID": ids[kind],
                "PayloadIdentifier": f"{base}.{kind}.{ids[kind]}", "PayloadDisplayName": name, **extra}

    content = [
        payload("root", "com.apple.security.root", "Wi-Fi server root CA",
                PayloadContent=root_der, PayloadCertificateFileName="Redis-Root-CA.cer"),
        payload("id", "com.apple.security.pkcs12", f"Wi-Fi certificate {device}",
                PayloadContent=pfx, PayloadCertificateFileName=f"{device}.pfx", Password=pfx_password),
        payload("wifi", "com.apple.wifi.managed", f"{ssid}",
                SSID_STR=ssid, HIDDEN_NETWORK=False, AutoJoin=True, EncryptionType="WPA2",
                IsHotspot=False, ProxyType="None", PayloadCertificateUUID=ids["id"],
                EAPClientConfiguration={"AcceptEAPTypes": [13], "UserName": device,
                                        "TLSTrustedServerNames": [server_name],
                                        "PayloadCertificateAnchorUUID": [ids["root"]]}),
    ]
    top = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadUUID": ids["top"],
           "PayloadIdentifier": f"{base}.{ids['top']}", "PayloadDisplayName": f"{ssid} Wi-Fi ({device})",
           "PayloadDescription": f"Connects this device to {ssid} with its own certificate. No password needed.",
           "PayloadRemovalDisallowed": False, "PayloadContent": content}
    return plistlib.dumps(top)
