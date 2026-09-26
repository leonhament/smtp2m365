# smtp2m365

A TLS-only SMTP gateway that lets printers, scanners and legacy applications send mail through **Exchange Online**, and that you deploy yourself in Azure.

Devices submit mail over SMTPS (465) or STARTTLS (587). The gateway checks the client IP, the SMTP credentials and the sender address, then hands the message to Exchange Online with an app-only OAuth token. **No API permission is consented in Entra ID.** The gateway can only send as the mailboxes you scope it to with [RBAC for Applications](https://learn.microsoft.com/exchange/permissions-exo/application-rbac).

```
printer / app ──TLS 465/587──▶ smtp2m365 ──OAuth (managed identity)──▶ Exchange Online
                                │ IP allowlist (NSG + gateway)
                                │ SMTP AUTH (PLAIN/LOGIN, bcrypt)
                                │ sender allow/deny (envelope + From:)
                                │ Let's Encrypt cert, auto-renewed
                                └ per-message report events
```

## Features

- **TLS only.** It serves implicit TLS on 465 and STARTTLS on 587. `AUTH` is not offered and `MAIL` is refused until TLS is up. The minimum version is TLS 1.2.
- **Automatic certificates.** Let's Encrypt certificates are issued and renewed with [certmagic](https://github.com/caddyserver/certmagic). The DNS-01 challenge runs against Azure DNS with the managed identity, so no inbound port 80 is needed. HTTP-01 and your own certificate files are also supported.
- **IP allowlist.** Disallowed clients are dropped before the TLS handshake. On Azure the NSG also enforces the list.
- **Sender policy.** Senders can be exact addresses, `@domain` or `*`. The deny list always wins, and you can add per-user restrictions. The policy checks both the envelope sender and the `From:` header.
- **Brute-force protection.** Client IPs are locked out after repeated authentication failures.
- **Two relay methods, both scoped by Exchange RBAC:**
  - `smtp` (default): SMTP client submission with XOAUTH2, using the role `Application SMTP.SendAsApp`. The message passes through unchanged, and messages up to 35 MB are supported.
  - `graph`: Graph `sendMail` with a MIME body, using the role `Application Mail.Send`. Messages are limited to 4 MB.
- **Synchronous relaying.** The device gets Exchange Online's real answer: `250` when delivered, `451` for temporary problems (so the device retries) and `554` with the reason for permanent rejections.
- **Reporting.** Each message writes one JSON log event (IP, user, sender, recipients, Message-ID, size, outcome, reason, latency). An admin API exposes stats and recent events. The gateway adds a Message-ID when a device leaves it out, so every message can be found in Exchange message trace.

## Deploy to Azure

Prerequisites:

- An Azure DNS zone for the gateway's hostname (for example `contoso.com` for `smtp.contoso.com`).
- A mail-enabled security group containing the mailboxes the gateway may send as (for example `smtp2m365-senders@contoso.com`).

### 1. Deploy the infrastructure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FOWNER%2Fsmtp2m365%2Fmain%2Fdeploy%2Fazure%2Fazuredeploy.json)

Or with the CLI:

```sh
az group create -n rg-smtp2m365 -l westeurope
az deployment group create -g rg-smtp2m365 -f deploy/azure/main.bicep -p \
  hostname=smtp.contoso.com dnsZoneName=contoso.com dnsZoneResourceGroup=rg-dns \
  acmeEmail=postmaster@contoso.com \
  allowedSourceAddresses='["198.51.100.10","203.0.113.0/28"]' \
  allowedSenders='["@contoso.com"]' \
  smtpUsers='{"users":[{"username":"printer-floor2","password_hash":"<hash>","allowed_senders":["scanner@contoso.com"]}]}' \
  sshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
```

The template creates:

- a small Ubuntu VM with a static public IP and a system-assigned managed identity;
- an NSG that allows only 465 and 587 from your allowlist (SSH stays closed);
- the DNS A record;
- a *DNS Zone Contributor* role assignment on the zone, used for Let's Encrypt.

Create password hashes with:

```sh
docker run --rm -it ghcr.io/OWNER/smtp2m365 hash-password
```

### 2. Grant the gateway access in Exchange Online

The deployment outputs `managedIdentityPrincipalId`. Use it to run the setup script:

```powershell
$objectId = '<managedIdentityPrincipalId>'
$appId    = az ad sp show --id $objectId --query appId -o tsv
./scripts/Setup-ExchangeRbac.ps1 -AppId $appId -ServicePrincipalObjectId $objectId `
    -SenderGroup smtp2m365-senders@contoso.com -EnableSmtpAuth
```

The script does four things:

1. Creates the Exchange service principal pointer.
2. Creates a management scope for the group's members.
3. Assigns `Application SMTP.SendAsApp` (or `Application Mail.Send` with `-Method Graph`) within that scope.
4. With `-EnableSmtpAuth`, turns on SMTP AUTH for those mailboxes. The `smtp` method requires this.

> Do **not** also grant `Mail.Send` or `SMTP.SendAsApp` in Entra ID. Entra grants are tenant-wide and are combined with the RBAC grant, which would remove the scoping.
>
> RBAC changes can take 30 minutes to 2 hours to apply. Until then, sends fail with `451` and devices retry.

### 3. Point devices at the gateway

| Setting | Value |
|---|---|
| Server | `smtp.contoso.com` |
| Port / encryption | 465 with SSL/TLS, or 587 with STARTTLS |
| Authentication | username and password from `users` |
| From address | a member of the sender group, allowed by `allowed_senders` |

## Configuration

See [`config.example.yaml`](config.example.yaml). `${VAR}` references are expanded from the environment. The Azure template writes the config to `/etc/smtp2m365/config.yaml` on the VM.

Credentials come from [`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/go/azure-sdk-authentication):

- **In Azure:** the managed identity.
- **Elsewhere, or to send into a different tenant:** set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and either `AZURE_CLIENT_SECRET` or `AZURE_CLIENT_CERTIFICATE_PATH`. Then run the RBAC script with that app registration's IDs.

## Reporting

- **Logs.** Each message produces one JSON line on stdout with `"msg":"smtp event"`. On the VM, view them with `journalctl -u smtp2m365` or `docker logs smtp2m365`.
- **Admin API.** It listens on `127.0.0.1:8080` by default. `/api/*` requires `Authorization: Bearer <admin.token>` when a token is set.
  - `GET /healthz`
  - `GET /api/stats`: counts of delivered, rejected and failed messages, plus dropped connections
  - `GET /api/events?limit=100`: most recent events, newest first

## Development

```sh
go test -race ./...
go run ./cmd/smtp2m365 -config config.yaml
```

Locally, `DefaultAzureCredential` falls back to your `az login` session. To test without Let's Encrypt, use `tls.mode: files` with a self-signed certificate.

## Roadmap

- Ship logs to Log Analytics (Azure Monitor Agent and a data collection rule), plus a workbook
- Built-in reporting web UI
- Persistent queue with retry, for devices that cannot retry on their own
- Graph large-message path (draft plus upload session)
- Azure Container Apps deployment option
- Configurable relaying for devices that support only plain port 25 (off by default)

## License

MIT
