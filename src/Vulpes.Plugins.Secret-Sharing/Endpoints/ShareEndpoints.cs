using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing.Endpoints;

public static class ShareEndpoints
{
    public static void Map(IEndpointRouteBuilder group)
    {
        group.MapGet("/crypto/params", () => Results.Json(new { udkWrapIterations = 893241, udkWrapHash = "SHA-512", skWrapIterations = 893241 }));
        group.MapGet("/user-data-key", GetKey);
        group.MapPut("/user-data-key", PutKey);
        group.MapDelete("/user-data-key/{kind}/{credentialId}", DeleteKey);
        group.MapGet("/home", Home);
        group.MapGet("/notifications", GetNotifications);
        group.MapPut("/notifications", PutNotifications);
        group.MapGet("/collect-retrieve-ips", GetCollectRetrieveIps).RequireAuthorization(Policies.Admin);
        group.MapPut("/collect-retrieve-ips", PutCollectRetrieveIps).RequireAuthorization(Policies.Admin);
        group.MapPost("/sends", CreateSend);
        group.MapDelete("/sends/{id}", DeleteSend);
        group.MapPost("/collects", CreateCollect).RequireAuthorization(Policies.Analyst);
        group.MapDelete("/collects/{id}", DeleteCollect).RequireAuthorization(Policies.Analyst);
        group.MapGet("/collects/{id}/owner-key", OwnerKey).RequireAuthorization(Policies.Analyst);
        group.MapPost("/public/collects/{id}/open", OpenCollect).AllowAnonymous();

        group.MapGet("/public/sends/{id}/pow", SendPow).AllowAnonymous();
        group.MapPost("/public/sends/{id}/meta", SendMeta).AllowAnonymous();
        group.MapPost("/public/sends/{id}", SendPayload).AllowAnonymous();
        group.MapGet("/public/collects/{id}/pow", CollectPow).AllowAnonymous();
        group.MapPost("/public/collects/{id}/meta", CollectMeta).AllowAnonymous();
        group.MapPost("/public/collects/{id}", CollectUpload).AllowAnonymous();
        group.MapMethods("/public/collects/{id}/upload-permit", ["GET", "HEAD"], CollectUploadPermit).AllowAnonymous();
    }

    private static IResult GetKey(HttpContext http, ShareStore store)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        return Results.Json(new
        {
            wrappedUserDataKey = store.GetWrappedUserDataKey(user),
            wraps = store.ListWraps(user).Select(w => new { kind = w.Kind, credentialId = w.CredentialId, wrapped = w.Wrapped }),
        });
    }

    private static async Task<IResult> PutKey(KeyBody body, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var kind = body.Kind;
        var wrapped = body.Wrapped;
        if (string.IsNullOrEmpty(kind) && !string.IsNullOrWhiteSpace(body.WrappedUserDataKey))
        {
            kind = "password";
            wrapped = body.WrappedUserDataKey;
        }

        if (kind is not ("password" or "passkey") || string.IsNullOrWhiteSpace(wrapped) || wrapped.Length > 8000 || !WrapPackage.IsValid(kind, wrapped))
        {
            return Results.BadRequest();
        }

        var credentialId = kind == "password" ? "" : body.CredentialId ?? "";
        if (kind == "passkey" && (credentialId.Length is < 1 or > 512 || !credentialId.All(IsTokenChar)))
        {
            return Results.BadRequest();
        }

        var first = store.UpsertWrap(user, kind, credentialId, wrapped);
        await audit.RecordAsync(first ? "secret.udk.created" : "secret.udk.wrapped", user, $"kind={kind}", cancellationToken: http.RequestAborted);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteKey(string kind, string credentialId, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        if (kind != "passkey" || credentialId.Length is < 1 or > 512 || !credentialId.All(IsTokenChar))
        {
            return Results.BadRequest();
        }

        if (!store.DeleteWrap(user, kind, credentialId)) return Results.NotFound();
        await audit.RecordAsync("secret.udk.removed", user, "kind=passkey", cancellationToken: http.RequestAborted);
        return Results.NoContent();
    }

    private static IResult Home(HttpContext http, ShareStore store)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var items = store.List(user);
        if (!ShareAccess.CanCollect(http.User))
        {
            items = items.Where(item => item.Kind != "collect").ToList();
        }

        return Results.Json(new { items });
    }

    internal static int ExpiryMinutes(int hours, int minutes)
    {
        if (minutes > 0)
        {
            return minutes;
        }

        if (hours <= 0)
        {
            return 0;
        }

        var scaled = (long)hours * 60L;
        return scaled > int.MaxValue ? int.MaxValue : (int)scaled;
    }

    private static async Task<IResult> CreateSend(SendBody body, HttpContext http, ShareStore store, IClientIpCapability ipCap, IUserEmail accounts, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var minutes = ExpiryMinutes(body.ExpiresInHours, body.ExpiresInMinutes);
        if (minutes is < 1 or > 64800)
        {
            return Results.BadRequest(new { error = "validation", message = "Choose an expiry between 1 minute and 45 days." });
        }

        if (!IpRestriction.TryNormalize(body.AllowedCidr, out var allowedCidr, out var cidrError))
        {
            return Results.BadRequest(new { error = "validation", message = cidrError });
        }

        if (!string.IsNullOrEmpty(allowedCidr) && allowedCidr != "*" && !ipCap.IpRestrictionsEnabled)
        {
            return Results.BadRequest(new { error = "validation", message = "IP restrictions are unavailable on this server because the client address is not a public visitor address. Leave Allowed IPs empty." });
        }

        if (body.EncryptedLabel is { Length: > 4096 } || body.RecipientLabel is { Length: > 8192 })
        {
            return Results.BadRequest(new { error = "validation", message = "Send name is too long." });
        }

        if (body.PrivateNoteCiphertext is { Length: > 30_000_000 })
        {
            return Results.BadRequest(new { error = "validation", message = "Private note is too long." });
        }

        if (body.Filename is { Length: > 200 })
        {
            return Results.BadRequest(new { error = "validation", message = "Filename is too long." });
        }

        var error = ValidatePayload(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey) ?? ValidateRecipientLabel(body.RecipientLabel);
        if (error is not null) return Results.BadRequest(new { error = "validation", message = error });
        if (!TryOpenCap(body.OneTime, body.MaxAccessCount, out var maxAccess))
        {
            return Results.BadRequest(new { error = "validation", message = OpenCapMessage });
        }

        await RememberLiveEmail(store, accounts, user);
        var id = store.CreateSend(user, new SendInput(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, Clip(body.ContentType, "application/octet-stream", 120), TrimOrNull(body.Filename), body.OneTime, minutes, TrimOrNull(body.EncryptedLabel), TrimOrNull(body.PrivateNoteCiphertext), maxAccess, body.PasswordProtected, body.HideTextByDefault, allowedCidr, TrimOrNull(body.RecipientLabel)));
        await audit.RecordAsync("secret.send.created", id, $"oneTime={body.OneTime} passwordProtected={body.PasswordProtected}", cancellationToken: http.RequestAborted);
        return Results.Json(new { id });
    }

    private static async Task<IResult> DeleteSend(string id, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        if (!store.DeleteSend(user, id)) return Results.NotFound();
        await audit.RecordAsync("secret.send.deleted", id, null, cancellationToken: http.RequestAborted);
        return Results.NoContent();
    }

    private static async Task<IResult> CreateCollect(CollectBody body, HttpContext http, ShareStore store, IUserEmail accounts, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var minutes = body.ExpiresInMinutes ?? ExpiryMinutes(body.ExpiresInHours, 0);
        if (!Base64Url.IsExact(body.PublicKey, 32) || minutes is < 1 or > 64800)
        {
            return Results.BadRequest(new { error = "validation", message = "Choose an expiry between 1 minute and 45 days." });
        }

        if (!SendCipher.ContributoryPublicKey(Base64Url.Decode(body.PublicKey)))
        {
            return Results.BadRequest(new { error = "validation", message = "Collect public key is not usable." });
        }

        if (!TryOpenCap(body.OneTime, body.MaxAccessCount, out var maxAccess))
        {
            return Results.BadRequest(new { error = "validation", message = OpenCapMessage });
        }

        if (body.PrivateNoteCiphertext is { Length: > 30_000_000 })
        {
            return Results.BadRequest(new { error = "validation", message = "Private note is too long." });
        }

        if (body.EncryptedLabel is { Length: > 4096 })
        {
            return Results.BadRequest(new { error = "validation", message = "Collect name is too long." });
        }

        if (body.OwnerPrivateKeyProtected is { Length: < 28 or > 4096 })
        {
            return Results.BadRequest(new { error = "validation", message = "Owner key has invalid length." });
        }

        var publicLabel = PublicLabelWire(body.PublicLabel);
        if (body.PublicLabel is not null && publicLabel is null)
        {
            return Results.BadRequest(new { error = "validation", message = "The collect name could not be stored." });
        }

        await RememberLiveEmail(store, accounts, user);
        var id = store.CreateCollect(user, new CollectInput(body.PublicKey, TrimOrNull(body.OwnerPrivateKeyProtected), TrimOrNull(body.EncryptedLabel), TrimOrNull(body.PrivateNoteCiphertext), body.OneTime, minutes, maxAccess, body.PasswordProtected, body.HideTextByDefault, publicLabel));
        await audit.RecordAsync("secret.collect.created", id, $"oneTime={body.OneTime} passwordProtected={body.PasswordProtected}", cancellationToken: http.RequestAborted);
        return Results.Json(new { id });
    }

    private static async Task<IResult> DeleteCollect(string id, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        if (!store.DeleteCollect(user, id)) return Results.NotFound();
        await audit.RecordAsync("secret.collect.deleted", id, null, cancellationToken: http.RequestAborted);
        return Results.NoContent();
    }

    private static async Task<IResult> OpenCollect(string id, PowBody? body, HttpContext http, ShareStore store, PowService pow, ShareScanGuard scan, IClientIpCapability ipCap, IHostAuditLog audit)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var browser = PowBrowser.Current(http);
        var held = pow.TryValidate("collect", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
        if (held is not null) return Denied(scan, http, held);
        var ready = store.CollectMeta(id);
        if (ready is not { Status: "ready" })
        {
            var spent = pow.TryConsume("collect", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
            return spent is not null ? Denied(scan, http, spent) : Miss(scan, http);
        }

        if (!IpRestriction.AllowsClient(store.CollectRetrieveAllowedIps(), http.Connection.RemoteIpAddress, ipCap.IpRestrictionsEnabled))
        {
            await audit.RecordAsync("secret.collect.ip_denied", id, "Collect retrieval denied: IP not allowed.", actor: UserId(http) ?? "anonymous", cancellationToken: http.RequestAborted);
            return CollectIpDenied(http);
        }

        var error = pow.TryConsume("collect", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
        if (error is not null) return Denied(scan, http, error);

        var row = store.TakeCollect(id);
        if (row is null) return Miss(scan, http);
        var actor = UserId(http) ?? "anonymous";
        await audit.RecordAsync("secret.collect.retrieved", id, "Collect retrieved.", actor: actor, cancellationToken: http.RequestAborted);
        return Results.Json(new { row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey, row.ContentType, row.Filename, row.HideTextByDefault, burned = row.Burned });
    }

    private static IResult OwnerKey(string id, HttpContext http, ShareStore store)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var key = store.OwnerKey(user, id);
        return key is null ? Results.NotFound() : Results.Json(new { ownerPrivateKeyProtected = key });
    }

    private static IResult SendPow(string id, PowService pow, ShareScanGuard scan, HttpContext http)
    {
        // Issue for any plausible id. Existence is checked only after the proof is burned.
        if (!Plausible(id)) return Miss(scan, http);
        if (FailureBudget(scan, http) is { } limited) return limited;
        var client = ShareScanGuard.ClientKey(http);
        if (!pow.TryIssue("send", id, client, PowBrowser.Current(http), out var challenge, out var retry) || challenge is null)
        {
            return TooMany(http, retry);
        }

        return Results.Json(challenge);
    }

    private static async Task<IResult> SendMeta(string id, PowBody body, ShareStore store, PowService pow, ShareScanGuard scan, IClientIpCapability ipCap, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var browser = PowBrowser.Current(http);
        var held = pow.TryValidate("send", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
        if (held is not null) return Denied(scan, http, held);
        var meta = store.SendMeta(id);
        if (meta is null || meta.Status != "active")
        {
            var spent = pow.TryConsume("send", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
            return spent is not null ? Denied(scan, http, spent) : Miss(scan, http);
        }

        if (!ClientAllowed(http, store, id, ipCap)) return await IpDenied(http, audit, id);
        var error = pow.TryConsume("send", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
        if (error is not null) return Denied(scan, http, error);
        return Results.Json(new
        {
            meta.Status,
            meta.ContentType,
            meta.Filename,
            meta.OneTime,
            meta.PasswordProtected,
            meta.HideTextByDefault,
            expiresAt = meta.ExpiresAt,
            accessCount = meta.AccessCount,
            maxAccessCount = meta.MaxAccessCount,
            encryptedLabel = meta.RecipientLabel,
            wrappedKey = meta.WrappedKey,
            ephemeralPublicKey = meta.EphemeralPublicKey,
        });
    }

    private static async Task<IResult> SendPayload(string id, PowBody? body, ShareStore store, PowService pow, ShareScanGuard scan, IClientIpCapability ipCap, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var browser = PowBrowser.Current(http);
        var held = pow.TryValidate("send", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
        if (held is not null) return Denied(scan, http, held);
        var peek = store.SendMeta(id);
        if (peek is null || peek.Status != "active")
        {
            var spent = pow.TryConsume("send", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
            return spent is not null ? Denied(scan, http, spent) : Miss(scan, http);
        }

        if (!ClientAllowed(http, store, id, ipCap)) return await IpDenied(http, audit, id);
        var error = pow.TryConsume("send", id, body?.ChallengeId, body?.Nonce, body?.Hash, browser, body?.ClientTime);
        if (error is not null) return Denied(scan, http, error);
        var row = store.TakeSend(id);
        if (row is null || row.Status != "active" || row.Ciphertext.Length == 0) return Miss(scan, http);
        await audit.RecordAsync("secret.send.decrypted", id, "Payload released.", actor: "anonymous", cancellationToken: http.RequestAborted);
        http.RequestServices.GetRequiredService<NotificationMail>().TrySendOpened(id);
        return Results.Json(new { row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey, row.ContentType, row.Filename, row.HideTextByDefault, burned = row.Burned });
    }

    private static IResult CollectPow(string id, PowService pow, ShareScanGuard scan, HttpContext http)
    {
        // Issue for any plausible id. Existence is checked only after the proof is burned.
        if (!Plausible(id)) return Miss(scan, http);
        if (FailureBudget(scan, http) is { } limited) return limited;
        var client = ShareScanGuard.ClientKey(http);
        if (!pow.TryIssue("collect", id, client, PowBrowser.Current(http), out var challenge, out var retry) || challenge is null)
        {
            return TooMany(http, retry);
        }

        return Results.Json(challenge);
    }

    private static async Task<IResult> CollectMeta(string id, PowBody body, ShareStore store, PowService pow, ShareScanGuard scan, IClientIpCapability ipCap, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var browser = PowBrowser.Current(http);
        var held = pow.TryValidate("collect", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
        if (held is not null) return Denied(scan, http, held);
        var meta = store.CollectMeta(id);
        if (meta is null || meta.Status is "expired" or "consumed")
        {
            var spent = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
            return spent is not null ? Denied(scan, http, spent) : Miss(scan, http);
        }

        // A waiting collect is an upload, so the retrieval allow-list does not apply.
        if (meta.Status == "ready" && !IpRestriction.AllowsClient(store.CollectRetrieveAllowedIps(), http.Connection.RemoteIpAddress, ipCap.IpRestrictionsEnabled))
        {
            await audit.RecordAsync("secret.collect.ip_denied", id, "Collect retrieval denied: IP not allowed.", actor: UserId(http) ?? "anonymous", cancellationToken: http.RequestAborted);
            return CollectIpDenied(http);
        }

        var error = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash, browser, body.ClientTime);
        if (error is not null) return Denied(scan, http, error);

        return Results.Json(new { meta.PublicKey, meta.Status, meta.OneTime, meta.PasswordProtected, meta.HideTextByDefault, meta.ExpiresAt, meta.Filename, accessCount = meta.AccessCount, maxAccessCount = meta.MaxAccessCount, hasPayload = meta.Status == "ready", publicLabel = meta.PublicLabel });
    }

    private static IResult CollectUploadPermit(string id, HttpContext http, PowService pow)
    {
        if (!Plausible(id)) return Results.StatusCode(StatusCodes.Status403Forbidden);
        PowService.ReadFromHeaders(http.Request.Headers, out var challenge, out var nonce, out var hash);
        if (challenge is null || nonce is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
        var error = pow.TryValidate("collect", id, challenge, nonce, hash, PowBrowser.Current(http), http.Request.Headers[PowService.HeaderTime].ToString());
        return error is null ? Results.NoContent() : Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    private static async Task<IResult> CollectUpload(string id, UploadBody body, ShareStore store, PowService pow, ShareScanGuard scan, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        if (!http.Items.ContainsKey(PowService.HttpContextPowConsumed))
        {
            var error = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash, PowBrowser.Current(http), body.ClientTime);
            if (error is not null) return Denied(scan, http, error);
        }
        var payloadError = ValidatePayload(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey);
        if (payloadError is not null) return Results.BadRequest(new { error = "payload", message = payloadError });
        var saved = store.SaveUpload(id, new UploadInput(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, Clip(body.ContentType, "application/octet-stream", 120), ClipOrNull(body.Filename, 200)));
        if (!saved) return Miss(scan, http);
        await audit.RecordAsync("secret.collect.uploaded", id, "Upload stored.", actor: "anonymous", cancellationToken: http.RequestAborted);
        http.RequestServices.GetRequiredService<NotificationMail>().TryCollectReady(id);
        return Results.NoContent();
    }

    private static string? ValidatePayload(string? ciphertext, string? iv, string? wrappedKey, string? ephemeral)
    {
        if (string.IsNullOrEmpty(ciphertext)) return "Ciphertext is required.";
        if (ciphertext.Length > ShareStore.MaxCipherChars) return "Payload exceeds maximum size.";
        if (!Base64Url.IsExact(iv, 12) || !Base64Url.IsExact(ephemeral, 32) || !Base64Url.IsExact(wrappedKey, 60)) return "Payload is not valid.";
        if (!SendCipher.ContributoryPublicKey(Base64Url.Decode(ephemeral!))) return "The encryption key is not usable.";
        return ciphertext.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_') ? null : "Payload is not valid.";
    }

    private static string? ValidateRecipientLabel(string? label)
    {
        if (string.IsNullOrEmpty(label)) return null;
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(label);
            if (!document.RootElement.TryGetProperty("ephemeralPublicKey", out var key) || key.ValueKind != System.Text.Json.JsonValueKind.String)
            {
                return "Send name is not valid.";
            }

            var text = key.GetString();
            if (!Base64Url.IsExact(text, 32) || !SendCipher.ContributoryPublicKey(Base64Url.Decode(text!)))
            {
                return "Send name is not valid.";
            }
        }
        catch (System.Text.Json.JsonException)
        {
            return "Send name is not valid.";
        }

        return null;
    }

    private static async Task<IResult> GetNotifications(HttpContext http, ShareStore store, IHostEmail mail, IUserEmail accounts)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var live = await LiveAccountEmail(accounts, user);
        var prefs = store.GetNotifications(user);
        if (live is null)
        {
            if (!string.IsNullOrEmpty(prefs.Email) || prefs.NotifyCollectReady || prefs.NotifySendOpened)
            {
                store.SaveNotifications(user, "", false, false);
                prefs = store.GetNotifications(user);
            }
        }
        else if (!string.Equals(prefs.Email, live, StringComparison.Ordinal))
        {
            store.RememberEmail(user, live);
            prefs = store.GetNotifications(user);
        }

        var canCollect = ShareAccess.CanCollect(http.User);
        var collect = canCollect && prefs.NotifyCollectReady;
        if (prefs.NotifyCollectReady && !canCollect)
        {
            store.SaveNotifications(user, live ?? "", false, prefs.NotifySendOpened);
        }

        var configured = await mail.IsConfiguredAsync(http.RequestAborted);
        return NotificationJson(live, collect, prefs.NotifySendOpened, canCollect, configured);
    }

    private static async Task<IResult> PutNotifications(NotificationBody body, HttpContext http, ShareStore store, IHostEmail mail, IUserEmail accounts, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var canCollect = ShareAccess.CanCollect(http.User);
        var collect = canCollect && body.NotifyCollectReady;
        var send = body.NotifySendOpened;
        var stored = store.GetNotifications(user);
        var turningOn = (collect && !stored.NotifyCollectReady) || (send && !stored.NotifySendOpened);
        var configured = await mail.IsConfiguredAsync(http.RequestAborted);
        if (turningOn && !configured)
        {
            return Results.BadRequest(new { error = "validation", message = "Email is not configured on this server." });
        }

        var live = await LiveAccountEmail(accounts, user);
        if (turningOn && live is null)
        {
            return Results.BadRequest(new { error = "validation", message = "Add an email address to this account before turning on these emails." });
        }

        store.SaveNotifications(user, live ?? "", collect, send);
        await audit.RecordAsync("secret.notify.changed", user, $"collectReady={collect} sendOpened={send}", cancellationToken: http.RequestAborted);
        return NotificationJson(live, collect, send, canCollect, configured);
    }

    private static IResult NotificationJson(string? email, bool collect, bool send, bool canCollect, bool mailConfigured) =>
        Results.Json(new { email, notifyCollectReady = collect, notifySendOpened = send, canCollect, mailConfigured });

    private static IResult GetCollectRetrieveIps(ShareStore store, IClientIpCapability ipCap) =>
        Results.Json(new { allowedIps = store.CollectRetrieveAllowedIps() ?? "", publicAddressVisible = ipCap.IpRestrictionsEnabled });

    private static async Task<IResult> PutCollectRetrieveIps(CollectRetrieveIpsBody body, HttpContext http, ShareStore store, IClientIpCapability ipCap, IHostAuditLog audit)
    {
        if (!IpRestriction.TryNormalize(body.AllowedIps, out var canonical, out var error))
        {
            return Results.BadRequest(new { error = "validation", message = error });
        }

        if (!string.IsNullOrEmpty(canonical) && canonical != "*" && !ipCap.IpRestrictionsEnabled)
        {
            return Results.BadRequest(new { error = "validation", message = "IP restrictions are unavailable on this server because the client address is not a public visitor address. Leave Allowed IPs empty." });
        }

        store.SaveCollectRetrieveAllowedIps(canonical);
        await audit.RecordAsync("secret.collect.retrieve_ips", "server", canonical ?? "(any)", cancellationToken: http.RequestAborted);
        return Results.Json(new { allowedIps = canonical ?? "", publicAddressVisible = ipCap.IpRestrictionsEnabled });
    }

    private sealed record CollectRetrieveIpsBody(string? AllowedIps);

    private static async Task RememberLiveEmail(ShareStore store, IUserEmail accounts, string userId)
    {
        var live = await LiveAccountEmail(accounts, userId);
        if (live is null)
        {
            var prefs = store.GetNotifications(userId);
            if (!string.IsNullOrEmpty(prefs.Email) || prefs.NotifyCollectReady || prefs.NotifySendOpened)
            {
                store.SaveNotifications(userId, "", false, false);
            }

            return;
        }

        store.RememberEmail(userId, live);
    }

    private static async Task<string?> LiveAccountEmail(IUserEmail accounts, string userId)
    {
        var live = (await accounts.GetEmailAsync(userId))?.Trim();
        return string.IsNullOrEmpty(live) ? null : live;
    }

    private static IResult Gone() =>
        Results.Json(new { error = "gone", message = "This secret is no longer available." }, statusCode: StatusCodes.Status404NotFound);

    private static IResult CollectIpDenied(HttpContext http) =>
        Results.Json(new { error = "ip", message = "Collecting this submission is not available from your IP address: " + SeenIp(http) }, statusCode: StatusCodes.Status403Forbidden);

    private static async Task<IResult> IpDenied(HttpContext http, IHostAuditLog audit, string id)
    {
        await audit.RecordAsync("secret.send.ip_denied", id, $"Send access denied: IP not allowed (id {id})", actor: "anonymous", cancellationToken: http.RequestAborted);
        return Results.Json(new { error = "ip", message = "This send is not available from your IP address: " + SeenIp(http) }, statusCode: StatusCodes.Status403Forbidden);
    }

    private static string SeenIp(HttpContext http)
    {
        var ip = http.Connection.RemoteIpAddress;
        if (ip is null)
        {
            return "unknown";
        }

        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    private static bool Plausible(string? id) => !string.IsNullOrEmpty(id) && id.Length is >= 1 and <= 128;

    private static IResult? FailureBudget(ShareScanGuard scan, HttpContext http)
    {
        var client = ShareScanGuard.ClientKey(http);
        return scan.IsFailureBudgetExceeded(client, out var retry) ? TooMany(http, retry) : null;
    }

    private static IResult Miss(ShareScanGuard scan, HttpContext http)
    {
        var client = ShareScanGuard.ClientKey(http);
        if (scan.IsFailureBudgetExceeded(client, out var retry)) return TooMany(http, retry);
        scan.RecordFailure(client);
        return Gone();
    }

    private static IResult Denied(ShareScanGuard scan, HttpContext http, string reason)
    {
        var client = ShareScanGuard.ClientKey(http);
        if (scan.IsFailureBudgetExceeded(client, out var retry)) return TooMany(http, retry);
        scan.RecordFailure(client);
        return Results.Json(new { error = "pow", message = reason }, statusCode: StatusCodes.Status403Forbidden);
    }

    private static IResult TooMany(HttpContext http, double retryAfterSeconds)
    {
        var seconds = Math.Max(1, (int)Math.Ceiling(retryAfterSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Results.Json(new { error = "rate_limit", message = "Too many failed attempts. Wait before trying again." }, statusCode: StatusCodes.Status429TooManyRequests);
    }

    private static bool ClientAllowed(HttpContext http, ShareStore store, string id, IClientIpCapability ipCap) =>
        IpRestriction.AllowsClient(store.AllowedCidr(id), http.Connection.RemoteIpAddress, ipCap.IpRestrictionsEnabled);

    private static string? UserId(HttpContext http) => http.User.FindFirstValue(ClaimTypes.NameIdentifier);

    private static string Clip(string? value, string fallback, int max)
    {
        var text = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        return text.Length <= max ? text : text[..max];
    }

    private static string? PublicLabelWire(PublicLabelBody? label)
    {
        if (label is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(label.Ciphertext) || string.IsNullOrWhiteSpace(label.Iv) || label.Ciphertext.Length > 4096 || label.Iv.Length > 64)
        {
            return null;
        }

        if (!label.Ciphertext.All(IsTokenChar) || !label.Iv.All(IsTokenChar))
        {
            return null;
        }

        return System.Text.Json.JsonSerializer.Serialize(new { v = label.V ?? 1, bound = string.IsNullOrWhiteSpace(label.Bound) ? "collect-pk-v2" : label.Bound, ciphertext = label.Ciphertext, iv = label.Iv });
    }

    private static bool IsTokenChar(char c) => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';

    internal const string OpenCapMessage = "Maximum access count must be a whole number from 1 to 100000.";

    private static bool TryOpenCap(bool oneTime, int? requested, out int? cap)
    {
        cap = null;
        if (oneTime || requested is null)
        {
            return true;
        }

        if (requested is < 1 or > 100000)
        {
            return false;
        }

        cap = requested;
        return true;
    }

    private static string? TrimOrNull(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? ClipOrNull(string? value, int max)
    {
        var text = TrimOrNull(value);
        return text is null || text.Length <= max ? text : text[..max];
    }

    private sealed record KeyBody(string? WrappedUserDataKey, string? Kind, string? CredentialId, string? Wrapped);
    private sealed record NotificationBody(bool NotifyCollectReady, bool NotifySendOpened);
    private sealed record SendBody(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string? ContentType, string? Filename, bool OneTime, int ExpiresInHours, int ExpiresInMinutes, string? EncryptedLabel, string? PrivateNoteCiphertext, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, string? AllowedCidr, string? RecipientLabel);
    private sealed record CollectBody(string PublicKey, string? OwnerPrivateKeyProtected, string? EncryptedLabel, string? PrivateNoteCiphertext, bool OneTime, int ExpiresInHours, int? ExpiresInMinutes, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, PublicLabelBody? PublicLabel);
    private sealed record PublicLabelBody(int? V, string? Bound, string? Ciphertext, string? Iv);
    private sealed record UploadBody(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string? ContentType, string? Filename, string? ChallengeId, string? Nonce, string? Hash, string? ClientTime);
    private sealed record PowBody(string? ChallengeId, string? Nonce, string? Hash, string? ClientTime);
}
