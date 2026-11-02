# Audit collection app registration

One Entra application for the whole dashboard. Add each customer directory under **Manage → Tenants** and consent
this same application in that directory. The client secret or certificate is stored once, encrypted with the dashboard
master key. Plugins share the application, so a new plugin adds its permissions to this registration instead of a
second application.

## Log collection app registration

1. **New registration**: name `Vulpes Collector`, **Accounts in any organizational directory** (multi-tenant), no redirect URI.
2. **Certificates & secrets**: client secret or certificate (certificates are recommended for long-lived automation).
3. **API permissions → Microsoft Graph → Application permissions**, then **Grant admin consent**:

| Permission | Used for |
| --- | --- |
| `AuditLog.Read.All` | Sign-in logs (interactive, non-interactive, service principal, managed identity), directory audits, provisioning logs |
| `Directory.Read.All` | Organisation name, sign-in enrichment |
| `AuditLogsQuery.Read.All` (or the per-workload set `AuditLogsQuery-SharePoint.Read.All`, `AuditLogsQuery-OneDrive.Read.All`, `AuditLogsQuery-Exchange.Read.All`, `AuditLogsQuery-Entra.Read.All`, `AuditLogsQuery-Endpoint.Read.All`, `AuditLogsQuery-CRM.Read.All`) | Purview unified audit log (`security/auditLog/queries`) |
| `SecurityAlert.Read.All` | Defender XDR alerts (`security/alerts_v2`) |
| `SecurityIncident.Read.All` | Defender XDR incidents |
| `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskyServicePrincipal.Read.All` | Identity Protection risk detections and risky identities |
| `SecurityEvents.Read.All` | Secure Score |
| `Organization.Read.All` (covered by `Directory.Read.All`) | Connection test |

Licensing notes: sign-in logs require Entra ID P1/P2; Identity Protection risk data requires P2; the unified audit log
requires Microsoft Purview Audit (Standard), which is included with the usual Microsoft 365 business and enterprise plans.

4. **Turn on Microsoft 365 audit logging** in the tenant you are collecting from. The Activity feed is the unified audit
   log. If recording is off, Exchange, SharePoint, OneDrive and Teams events are never written, and the collector has
   nothing to fetch.

   - In the [Purview portal](https://purview.microsoft.com) or the [Defender portal](https://security.microsoft.com),
     open **Audit**. If the banner **Start recording user and admin activity** is shown, select it. If the banner is
     absent, recording is already on. You need the Audit Logs role, or Compliance Administrator or Global Administrator.
   - Or with Exchange Online PowerShell:

```powershell
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

   The change can take up to 60 minutes. Mailbox auditing is on by default and is what produces Exchange item activity
   (mail read, send, delete). Confirm it has not been switched off:

```powershell
Get-OrganizationConfig | Format-List AuditDisabled
```

   `AuditDisabled` must be `False`.

5. In each customer directory, grant admin consent for this application
   (`https://login.microsoftonline.com/{directory-id}/adminconsent?client_id={application-id}`).
6. In the dashboard open **Manage → Tenants**. Save the application client id, cloud, and secret or PFX once.
   Add each directory id, then run **Test connection**. Each log source shows `ok`, `forbidden` (permission missing),
   `skipped`, or `error`.
7. Open the plugin's **Permissions diagnostic**. It lists any required application permission that is not granted
   in that directory. Grant the missing permission on the shared application and consent again.

The collector sends app-only requests to `graph.microsoft.com` (or `graph.microsoft.us`) only; it never follows
continuation links to other hosts and honours `Retry-After` on throttling.
