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
        group.MapPost("/sends", CreateSend);
        group.MapDelete("/sends/{id}", DeleteSend);
        group.MapPost("/collects", CreateCollect);
        group.MapDelete("/collects/{id}", DeleteCollect);
        group.MapGet("/collects/{id}/owner-key", OwnerKey);
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
        return Results.Json(new { items = store.List(user) });
    }

    private static async Task<IResult> CreateSend(SendBody body, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var minutes = body.ExpiresInMinutes > 0 ? body.ExpiresInMinutes : body.ExpiresInHours > 0 ? body.ExpiresInHours * 60 : 0;
        if (minutes is < 1 or > 64800)
        {
            return Results.BadRequest(new { error = "validation", message = "Choose an expiry between 1 minute and 45 days." });
        }

        if (!IpRestriction.TryNormalize(body.AllowedCidr, out var allowedCidr, out var cidrError))
        {
            return Results.BadRequest(new { error = "validation", message = cidrError });
        }

        var error = ValidatePayload(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, 1);
        if (error is not null) return Results.BadRequest();
        RememberEmail(http, store, user);
        var id = store.CreateSend(user, new SendInput(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, Clip(body.ContentType, "application/octet-stream", 120), ClipOrNull(body.Filename, 200), body.OneTime, minutes, ClipOrNull(body.EncryptedLabel, 2000), ClipOrNull(body.PrivateNoteCiphertext, 8000), body.MaxAccessCount is > 0 and <= 100000 ? body.MaxAccessCount : null, body.PasswordProtected, body.HideTextByDefault, allowedCidr, ClipOrNull(body.RecipientLabel, 8000)));
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

    private static async Task<IResult> CreateCollect(CollectBody body, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var minutes = body.ExpiresInMinutes ?? (body.ExpiresInHours > 0 ? body.ExpiresInHours * 60 : 0);
        if (!Base64Url.IsExact(body.PublicKey, 32) || minutes is < 1 or > 64800)
        {
            return Results.BadRequest(new { error = "validation", message = "Choose an expiry between 1 minute and 45 days." });
        }

        if (!body.OneTime && body.MaxAccessCount is int max && max is < 1 or > 100000)
        {
            return Results.BadRequest(new { error = "validation", message = "Maximum access count must be between 1 and 100000." });
        }

        if (body.PrivateNoteCiphertext is { Length: > 30_000_000 } || body.EncryptedLabel is { Length: > 4096 })
        {
            return Results.BadRequest(new { error = "validation", message = "That field is too long." });
        }

        var publicLabel = PublicLabelWire(body.PublicLabel);
        if (body.PublicLabel is not null && publicLabel is null)
        {
            return Results.BadRequest(new { error = "validation", message = "The collect name could not be stored." });
        }

        RememberEmail(http, store, user);
        var id = store.CreateCollect(user, new CollectInput(body.PublicKey, ClipOrNull(body.OwnerPrivateKeyProtected, 8000), body.EncryptedLabel, body.PrivateNoteCiphertext, body.OneTime, minutes, body.OneTime ? null : body.MaxAccessCount is > 0 and <= 100000 ? body.MaxAccessCount : null, body.PasswordProtected, body.HideTextByDefault, publicLabel));
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

    private static async Task<IResult> OpenCollect(string id, PowBody body, HttpContext http, ShareStore store, PowService pow, ShareScanGuard scan, IHostAuditLog audit)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var error = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash);
        if (error is not null) return Denied(scan, http, error);
        var row = store.TakeCollect(id);
        if (row is null) return Miss(scan, http);
        var actor = UserId(http) ?? "anonymous";
        await audit.RecordAsync("secret.collect.retrieved", id, "Collect retrieved.", actor: actor, cancellationToken: http.RequestAborted);
        return Results.Json(new { row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey, row.ContentType, row.Filename, row.HideTextByDefault });
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
        if (Budget(scan, http) is { } limited) return limited;
        var challenge = pow.Issue("send", id);
        scan.RecordChallengeIssue(ShareScanGuard.ClientKey(http));
        return Results.Json(challenge);
    }

    private static IResult SendMeta(string id, PowBody body, ShareStore store, PowService pow, ShareScanGuard scan, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var error = pow.TryConsume("send", id, body.ChallengeId, body.Nonce, body.Hash);
        if (error is not null) return Denied(scan, http, error);
        var meta = store.SendMeta(id);
        if (meta is null || meta.Status != "active" || !ClientAllowed(http, store, id)) return Miss(scan, http);
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
        });
    }

    private static async Task<IResult> SendPayload(string id, PowBody body, ShareStore store, PowService pow, ShareScanGuard scan, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var error = pow.TryConsume("send", id, body.ChallengeId, body.Nonce, body.Hash);
        if (error is not null) return Denied(scan, http, error);
        if (!ClientAllowed(http, store, id)) return Miss(scan, http);
        var row = store.TakeSend(id);
        if (row is null || row.Status != "active" || row.Ciphertext.Length == 0) return Miss(scan, http);
        await audit.RecordAsync("secret.send.decrypted", id, "Payload released after proof of work.", actor: "anonymous", cancellationToken: http.RequestAborted);
        http.RequestServices.GetRequiredService<NotificationMail>().TrySendOpened(id);
        return Results.Json(new { row.Ciphertext, row.Iv, row.WrappedKey, row.EphemeralPublicKey, row.ContentType, row.Filename, row.HideTextByDefault });
    }

    private static IResult CollectPow(string id, PowService pow, ShareScanGuard scan, HttpContext http)
    {
        // Issue for any plausible id. Existence is checked only after the proof is burned.
        if (!Plausible(id)) return Miss(scan, http);
        if (Budget(scan, http) is { } limited) return limited;
        var challenge = pow.Issue("collect", id);
        scan.RecordChallengeIssue(ShareScanGuard.ClientKey(http));
        return Results.Json(challenge);
    }

    private static IResult CollectMeta(string id, PowBody body, ShareStore store, PowService pow, ShareScanGuard scan, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        var error = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash);
        if (error is not null) return Denied(scan, http, error);
        var meta = store.CollectMeta(id);
        if (meta is null || meta.Status is "expired" or "consumed") return Miss(scan, http);
        return Results.Json(new { meta.PublicKey, meta.Status, meta.OneTime, meta.PasswordProtected, meta.HideTextByDefault, meta.ExpiresAt, meta.Filename, accessCount = meta.AccessCount, maxAccessCount = meta.MaxAccessCount, hasPayload = meta.Status == "ready", publicLabel = meta.PublicLabel });
    }

    private static IResult CollectUploadPermit(string id, HttpContext http, ShareStore store, PowService pow)
    {
        if (!Plausible(id)) return Results.StatusCode(StatusCodes.Status403Forbidden);
        PowService.ReadFromHeaders(http.Request.Headers, out var challenge, out var nonce, out var hash);
        var meta = store.CollectMeta(id);
        if (meta is null || meta.Status != "waiting") return Results.StatusCode(StatusCodes.Status403Forbidden);
        var error = pow.TryValidate("collect", id, challenge, nonce, hash);
        return error is null ? Results.NoContent() : Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    private static async Task<IResult> CollectUpload(string id, UploadBody body, ShareStore store, PowService pow, ShareScanGuard scan, IHostAuditLog audit, HttpContext http)
    {
        if (FailureBudget(scan, http) is { } limited) return limited;
        if (!Plausible(id)) return Miss(scan, http);
        if (!http.Items.ContainsKey(PowService.HttpContextPowConsumed))
        {
            var error = pow.TryConsume("collect", id, body.ChallengeId, body.Nonce, body.Hash);
            if (error is not null) return Denied(scan, http, error);
        }
        var payloadError = ValidatePayload(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, 1);
        if (payloadError is not null) return Results.BadRequest(new { error = "payload", message = payloadError });
        var saved = store.SaveUpload(id, new UploadInput(body.Ciphertext, body.Iv, body.WrappedKey, body.EphemeralPublicKey, Clip(body.ContentType, "application/octet-stream", 120), ClipOrNull(body.Filename, 200)));
        if (saved is not null) return Results.Conflict(new { error = "conflict", message = saved });
        await audit.RecordAsync("secret.collect.uploaded", id, "Upload stored.", actor: "anonymous", cancellationToken: http.RequestAborted);
        http.RequestServices.GetRequiredService<NotificationMail>().TryCollectReady(id);
        return Results.NoContent();
    }

    private static string? ValidatePayload(string? ciphertext, string? iv, string? wrappedKey, string? ephemeral, int hours)
    {
        if (hours is < 1 or > 720) return "Choose an expiry between 1 minute and 30 days.";
        if (string.IsNullOrEmpty(ciphertext)) return "Ciphertext is required.";
        if (ciphertext.Length > ShareStore.MaxCipherChars) return "Payload exceeds maximum size.";
        if (!Base64Url.IsExact(iv, 12) || !Base64Url.IsExact(ephemeral, 32) || !Base64Url.IsExact(wrappedKey, 60)) return "Payload is not valid.";
        return ciphertext.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_') ? null : "Payload is not valid.";
    }

    private static IResult GetNotifications(HttpContext http, ShareStore store)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var email = Email(http);
        if (email is not null) store.RememberEmail(user, email);
        var prefs = store.GetNotifications(user);
        return Results.Json(new { email = email ?? (string.IsNullOrEmpty(prefs.Email) ? null : prefs.Email), notifyCollectReady = prefs.NotifyCollectReady, notifySendOpened = prefs.NotifySendOpened });
    }

    private static async Task<IResult> PutNotifications(NotificationBody body, HttpContext http, ShareStore store, IHostAuditLog audit)
    {
        var user = UserId(http);
        if (user is null) return Results.Unauthorized();
        var email = Email(http) ?? "";
        if ((body.NotifyCollectReady || body.NotifySendOpened) && email.Length == 0)
        {
            return Results.BadRequest(new { error = "validation", message = "Add an email address to this account before turning on these emails." });
        }

        store.SaveNotifications(user, email, body.NotifyCollectReady, body.NotifySendOpened);
        await audit.RecordAsync("secret.notify.changed", user, $"collectReady={body.NotifyCollectReady} sendOpened={body.NotifySendOpened}", cancellationToken: http.RequestAborted);
        return Results.Json(new { email = email.Length == 0 ? null : email, notifyCollectReady = body.NotifyCollectReady, notifySendOpened = body.NotifySendOpened });
    }

    private static void RememberEmail(HttpContext http, ShareStore store, string userId)
    {
        var email = Email(http);
        if (email is not null) store.RememberEmail(userId, email);
    }

    private static IResult Gone() =>
        Results.Json(new { error = "gone", message = "This secret is no longer available." }, statusCode: StatusCodes.Status404NotFound);

    private static bool Plausible(string? id) => !string.IsNullOrEmpty(id) && id.Length is >= 1 and <= 128;

    private static IResult? Budget(ShareScanGuard scan, HttpContext http)
    {
        var client = ShareScanGuard.ClientKey(http);
        if (scan.IsFailureBudgetExceeded(client, out var retry) || scan.IsChallengeIssueBudgetExceeded(client, out retry))
        {
            return TooMany(http, retry);
        }

        return null;
    }

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

    private static bool ClientAllowed(HttpContext http, ShareStore store, string id) =>
        IpRestriction.IsClientAllowed(store.AllowedCidr(id), http.Connection.RemoteIpAddress);

    private static string? UserId(HttpContext http) => http.User.FindFirstValue(ClaimTypes.NameIdentifier);

    private static string? Email(HttpContext http)
    {
        var value = http.User.FindFirstValue(ClaimTypes.Email);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

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

    private static string? ClipOrNull(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        return text.Length <= max ? text : text[..max];
    }

    private sealed record KeyBody(string? WrappedUserDataKey, string? Kind, string? CredentialId, string? Wrapped);
    private sealed record NotificationBody(bool NotifyCollectReady, bool NotifySendOpened);
    private sealed record SendBody(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string? ContentType, string? Filename, bool OneTime, int ExpiresInHours, int ExpiresInMinutes, string? EncryptedLabel, string? PrivateNoteCiphertext, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, string? AllowedCidr, string? RecipientLabel);
    private sealed record CollectBody(string PublicKey, string? OwnerPrivateKeyProtected, string? EncryptedLabel, string? PrivateNoteCiphertext, bool OneTime, int ExpiresInHours, int? ExpiresInMinutes, int? MaxAccessCount, bool PasswordProtected, bool HideTextByDefault, PublicLabelBody? PublicLabel);
    private sealed record PublicLabelBody(int? V, string? Bound, string? Ciphertext, string? Iv);
    private sealed record UploadBody(string Ciphertext, string Iv, string WrappedKey, string EphemeralPublicKey, string? ContentType, string? Filename, string? ChallengeId, string? Nonce, string? Hash);
    private sealed record PowBody(string? ChallengeId, string? Nonce, string? Hash);
}
