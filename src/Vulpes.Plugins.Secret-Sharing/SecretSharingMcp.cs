using System.Text.Json;
using System.Text.Json.Nodes;
using Vulpes.Plugins.SecretSharing.Endpoints;
using Vulpes.Plugins.SecretSharing.Services;
using Vulpes.Sdk;

namespace Vulpes.Plugins.SecretSharing;

/// <summary>One-way sends for a bot. The bot cannot create or read a collect.</summary>
public sealed class SecretSharingMcp(ShareStore store, IHostEmail email, IClientIpCapability addresses) : IMcpToolSource
{
    public string PluginId => "secret-sharing";

    public const string DisclosureWarning = "Any secret you submit will be visible to the assistant handling this request. Consider that before proceeding.";

    public string Instructions =>
        """
        Before you ask for a secret, accept a secret, or call create_secret, tell the user: "Any secret you submit will be visible to the assistant handling this request. Consider that before proceeding." Wait for an explicit approval to proceed despite that risk. Do not request the secret, do not take a secret the user has already offered, and do not attempt the send until that warning has been shown and that approval has been given. Set disclosureAccepted to true only after that approval.

        When emailTo is set, tell the user the exact address or addresses the link will be sent to and wait for them to confirm. Do not send the email until they confirm. Set emailConfirmed to true only after that confirmation. Those addresses are the only recipients. The link cannot be emailed to any further address afterwards.

        You can create a secret send the same way a person does: a title, a private note, text or a file up to 40 MB, an optional link password, an optional IP allow-list, masked or visible text, one-time or a limited number of opens, and an expiry. The link is returned once in this result, or emailed when emailTo is set. It is never stored. list_secrets does not return it. Vulpes does not keep the decryption key or the password.

        A title and a private note are sealed with this bot's user data key. That key is derived from the bot token and a random salt stored for the token. Only this token can read them. list_secrets returns those fields. It does not return the secret payload.

        You cannot create a collect link, upload to a collect, or read a collected secret.
        """;

    public IReadOnlyList<McpTool> Tools => Catalog;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static readonly IReadOnlyList<McpTool> Catalog =
    [
        Define("create_secret", "Create a one-way secret send. The link is returned once, or emailed, and is never stored. Does not create a collect. Before asking for a secret, accepting one, or calling this tool, tell the user: \"" + DisclosureWarning + "\" Then wait for an explicit approval to proceed despite that risk. Do not request or take the secret until that approval. Set disclosureAccepted to true only after it. When emailTo is set, tell the user those exact addresses and wait for them to confirm. Set emailConfirmed to true only after that confirmation. The addresses on this call are the only recipients; the link cannot be emailed to any further address.", new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject
            {
                ["text"] = new JsonObject { ["type"] = "string", ["description"] = "The secret text. Use this or fileBase64, not both." },
                ["fileBase64"] = new JsonObject { ["type"] = "string", ["description"] = "File bytes, standard base64. At most 40 MB decoded." },
                ["filename"] = new JsonObject { ["type"] = "string", ["description"] = "File name. Required with fileBase64. At most 200 characters." },
                ["contentType"] = new JsonObject { ["type"] = "string", ["description"] = "File media type. Default application/octet-stream." },
                ["password"] = new JsonObject { ["type"] = "string", ["description"] = "Optional link password. Share it separately. It is not stored." },
                ["allowedIps"] = new JsonObject { ["type"] = "string", ["description"] = "Optional comma-separated IP addresses or CIDR ranges." },
                ["title"] = new JsonObject { ["type"] = "string", ["description"] = "Optional send name. At most 256 characters. Sealed for this bot and also shown to the recipient. label is the same field." },
                ["label"] = new JsonObject { ["type"] = "string", ["description"] = "Same as title." },
                ["privateNote"] = new JsonObject { ["type"] = "string", ["description"] = "Optional note only this bot can read. It is not part of the secret." },
                ["expiresInMinutes"] = new JsonObject { ["type"] = "integer", ["description"] = "How long the link works. 1 to 64800 minutes. Default 10080 (7 days)." },
                ["oneTime"] = new JsonObject { ["type"] = "boolean", ["description"] = "When true, the link works once. Default false, which is multiple use." },
                ["maxAccessCount"] = new JsonObject { ["type"] = "integer", ["description"] = "How many times a multiple-use link can be opened. 1 to 100000. Omit for no limit. Ignored when oneTime is true." },
                ["hideText"] = new JsonObject { ["type"] = "boolean", ["description"] = "When true, the recipient page masks the secret until they choose to show it. Ignored for a file. Default false." },
                ["emailTo"] = new JsonObject { ["type"] = "string", ["description"] = "Optional. Email the link to these addresses, separated by commas. Tell the user the exact addresses and wait for them to confirm before sending. That list is final: the link cannot be emailed to any further address." },
                ["emailConfirmed"] = new JsonObject { ["type"] = "boolean", ["description"] = "Required when emailTo is set. True only after the user has confirmed that the link should be sent to that exact address." },
                ["disclosureAccepted"] = new JsonObject { ["type"] = "boolean", ["description"] = "Required. True only after you have shown the user this warning, and the user has explicitly approved proceeding despite that risk: " + DisclosureWarning },
            },
            ["required"] = new JsonArray("disclosureAccepted"),
        }),
        Define("list_secrets", "List this bot's sends, including the title and private note. Never includes the link, the decryption key, or the secret payload.", new JsonObject
        {
            ["type"] = "object",
            ["properties"] = new JsonObject(),
        }),
    ];

    public ValueTask<McpToolResult> CallAsync(string name, JsonElement arguments, CancellationToken cancellationToken) =>
        CallAsync(name, arguments, default, cancellationToken);

    public async ValueTask<McpToolResult> CallAsync(string name, JsonElement arguments, McpCaller caller, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (!caller.HasUserDataKey || string.IsNullOrEmpty(caller.TokenId))
            {
                throw new ArgumentException("This bot has no user data key.");
            }

            var payload = name switch
            {
                "create_secret" => await Create(arguments, caller),
                "list_secrets" => List(caller),
                _ => throw new ArgumentException($"Unknown tool '{name}'."),
            };
            var json = payload.ToJsonString(Json);
            return new McpToolResult(json, json);
        }
        catch (ArgumentException ex)
        {
            return new McpToolResult(ex.Message, IsError: true);
        }
    }

    private const int FileLimit = 40 * 1024 * 1024;

    private async Task<JsonObject> Create(JsonElement args, McpCaller caller)
    {
        if (!Flag(args, "disclosureAccepted"))
        {
            throw new ArgumentException("Do not send a secret yet. Tell the user: \"" + DisclosureWarning + "\" Wait for an explicit approval to proceed despite that risk. Do not ask for the secret or take one until then. Call create_secret with disclosureAccepted true only after that approval.");
        }

        var text = Optional(args, "text");
        var fileText = Optional(args, "fileBase64");
        var hasText = !string.IsNullOrEmpty(text);
        var hasFile = !string.IsNullOrWhiteSpace(fileText);
        if (hasText == hasFile)
        {
            throw new ArgumentException("Send either text or a file.");
        }

        byte[] plain;
        string contentType;
        string? filename = null;
        if (hasFile)
        {
            filename = Optional(args, "filename")?.Trim();
            if (string.IsNullOrEmpty(filename) || filename.Length > 200)
            {
                throw new ArgumentException("A file name is required and must be 200 characters or fewer.");
            }

            plain = DecodeFile(fileText!);
            if (plain.Length > FileLimit)
            {
                throw new ArgumentException("File exceeds 40 MB limit.");
            }

            contentType = Optional(args, "contentType")?.Trim() ?? "";
            if (contentType.Length == 0)
            {
                contentType = "application/octet-stream";
            }

            if (contentType.Length > 120)
            {
                throw new ArgumentException("Content type is too long.");
            }
        }
        else
        {
            if (text!.Length > 1_000_000)
            {
                throw new ArgumentException("Secret text is too long (max 1000000 characters).");
            }

            plain = System.Text.Encoding.UTF8.GetBytes(text);
            contentType = "text/plain";
        }

        var label = Optional(args, "title")?.Trim();
        if (string.IsNullOrEmpty(label))
        {
            label = Optional(args, "label")?.Trim();
        }
        if (label is { Length: > 256 })
        {
            throw new ArgumentException("Send name is too long (max 256 characters).");
        }

        var note = Optional(args, "privateNote")?.Trim();
        if (note is { Length: > 5_000_000 })
        {
            throw new ArgumentException("Private note is too long.");
        }

        var minutes = Int(args, "expiresInMinutes") ?? 10080;
        if (minutes is < 1 or > 64800)
        {
            throw new ArgumentException("Choose an expiry between 1 minute and 45 days.");
        }

        var oneTime = Flag(args, "oneTime");
        int? maxAccess = null;
        if (!oneTime && Int(args, "maxAccessCount") is int max)
        {
            if (max is < 1 or > 100000)
            {
                throw new ArgumentException(ShareEndpoints.OpenCapMessage);
            }

            maxAccess = max;
        }

        if (!IpRestriction.TryNormalize(Optional(args, "allowedIps"), out var allowedIps, out var ipError))
        {
            throw new ArgumentException(ipError ?? "Allowed IPs are not valid.");
        }

        if (!string.IsNullOrEmpty(allowedIps) && allowedIps != "*" && !addresses.IpRestrictionsEnabled)
        {
            throw new ArgumentException("IP restrictions are unavailable on this server because the client address is not a public visitor address. Leave Allowed IPs empty.");
        }

        var password = Optional(args, "password") ?? "";
        if (password.Length > 256)
        {
            throw new ArgumentException("A link password must be 256 characters or fewer.");
        }

        var hideText = !hasFile && Flag(args, "hideText");
        var emailTo = Optional(args, "emailTo")?.Trim() ?? "";
        string[] recipients;
        try
        {
            recipients = emailTo.Length == 0 ? [] : ParseRecipients(emailTo);
        }
        catch
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
            throw;
        }

        if (recipients.Length > 0 && !Flag(args, "emailConfirmed"))
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
            throw new ArgumentException("Do not email the link yet. Tell the user the link will be sent to " + string.Join(", ", recipients) + " and wait for them to confirm those addresses. Call create_secret again with emailConfirmed true only after they confirm.");
        }

        var wire = SendCipher.Encrypt(plain, out var secret);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
        try
        {
            var udk = caller.UserDataKey.Span;
            string? ownerLabel = null;
            string? recipientLabel = null;
            if (!string.IsNullOrEmpty(label))
            {
                ownerLabel = SendCipher.SealOwnerField(label, udk);
                recipientLabel = SendCipher.RecipientLabel(System.Text.Encoding.UTF8.GetBytes(label), X25519.ScalarMultBase(secret));
            }

            var ownerNote = string.IsNullOrEmpty(note) ? null : SendCipher.SealOwnerField(note, udk);
            var fragment = password.Length == 0
                ? "#sk=" + Base64Url.Encode(secret)
                : "#sk=" + Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes(SendCipher.WrapSecretKey(secret, password)));
            var id = store.CreateSend("bot:" + caller.TokenId, new SendInput(
                wire.Ciphertext,
                wire.Iv,
                wire.WrappedKey,
                wire.EphemeralPublicKey,
                contentType,
                filename,
                oneTime,
                minutes,
                ownerLabel,
                ownerNote,
                maxAccess,
                password.Length > 0,
                hideText,
                allowedIps,
                recipientLabel));
            var origin = email.PublicOrigin.TrimEnd('/');
            var link = origin + "/send?id=" + Uri.EscapeDataString(id) + fragment;
            var emailed = false;
            if (recipients.Length > 0)
            {
                try
                {
                    if (!store.SealEmailRecipients(id, string.Join(", ", recipients)))
                    {
                        throw new ArgumentException("This link has already been emailed. It cannot be sent to any further address. " + link);
                    }
                }
                catch (InvalidOperationException)
                {
                    // No data key is available, so the addresses are not stored. The mail still goes out.
                }
                catch (ArgumentException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // The ciphertext is already stored. The link is the only copy of the key, so the tool error has to carry it.
                    throw new ArgumentException("The recipient list could not be stored. The link is still valid: " + link, ex);
                }

                var subject = password.Length > 0 ? "Secret link (password required)" : "Secret link";
                var sentence = password.Length > 0
                    ? "A secret link is below. The password was shared separately and is not in this message."
                    : "A secret link is below. The decryption key is part of the link. This link is not stored.";
                emailed = true;
                foreach (var recipient in recipients)
                {
                    var sent = await email.TrySendAsync(recipient, subject, sentence + "\n\n" + link, "<p>" + System.Net.WebUtility.HtmlEncode(sentence) + "</p><p>" + System.Net.WebUtility.HtmlEncode(link) + "</p>");
                    emailed = emailed && sent;
                }
            }

            return new JsonObject
            {
                ["id"] = id,
                ["link"] = link,
                ["emailed"] = emailed,
                ["expiresInMinutes"] = minutes,
                ["oneTime"] = oneTime,
                ["maxAccessCount"] = maxAccess,
                ["hideText"] = hideText,
                ["passwordProtected"] = password.Length > 0,
                ["filename"] = filename,
            };
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static string[] ParseRecipients(string raw)
    {
        var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length is < 1 or > 10)
        {
            throw new ArgumentException("emailTo must be one to ten email addresses, separated by commas.");
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recipients = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (part.Length > 254 || !System.Net.Mail.MailAddress.TryCreate(part, out var parsed) || !parsed.Address.Equals(part, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("emailTo must be an email address.");
            }

            if (seen.Add(parsed.Address))
            {
                recipients.Add(parsed.Address);
            }
        }

        return recipients.ToArray();
    }

    private static byte[] DecodeFile(string value)
    {
        var text = value.Trim();
        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            try
            {
                return Base64Url.Decode(text);
            }
            catch (FormatException)
            {
                throw new ArgumentException("fileBase64 is not valid base64.");
            }
        }
    }

    private JsonObject List(McpCaller caller)
    {
        var rows = new JsonArray();
        foreach (var item in store.List("bot:" + caller.TokenId))
        {
            if (item.Kind != "send")
            {
                continue;
            }

            rows.Add(new JsonObject
            {
                ["id"] = item.Id,
                ["status"] = item.Status,
                ["oneTime"] = item.OneTime,
                ["maxAccessCount"] = item.MaxAccessCount,
                ["accessCount"] = item.AccessCount,
                ["hideText"] = item.HideText,
                ["passwordProtected"] = item.PasswordProtected,
                ["ipRestricted"] = item.IpRestricted,
                ["createdAt"] = item.CreatedAt.ToString("O"),
                ["expiresAt"] = item.ExpiresAt.ToString("O"),
                ["label"] = SendCipher.OpenOwnerField(item.EncryptedLabel, caller.UserDataKey.Span),
                ["privateNote"] = SendCipher.OpenOwnerField(item.PrivateNoteCiphertext, caller.UserDataKey.Span),
            });
        }

        return new JsonObject { ["secrets"] = rows };
    }

    private static string Required(JsonElement args, string name)
    {
        var value = Optional(args, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{name} is required.");
        }

        return value;
    }

    private static string? Optional(JsonElement args, string name) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? Int(JsonElement args, string name)
    {
        if (args.ValueKind != JsonValueKind.Object || !args.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        throw new ArgumentException($"{name} must be an integer.");
    }

    private static bool Flag(JsonElement args, string name)
    {
        if (args.ValueKind != JsonValueKind.Object || !args.TryGetProperty(name, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new ArgumentException($"{name} must be true or false."),
        };
    }

    private static McpTool Define(string name, string description, JsonObject schema) => new(name, description, schema.ToJsonString(Json));
}
