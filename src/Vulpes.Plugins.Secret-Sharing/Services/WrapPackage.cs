using System.Text.Json;

namespace Vulpes.Plugins.SecretSharing.Services;

/// <summary>Rejects a user-data-key wrap that is not the package this plugin creates.</summary>
public static class WrapPackage
{
    public const int PasswordIterations = 893241;

    public static bool IsValid(string kind, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.GetProperty("v").GetInt32() != 1)
            {
                return false;
            }

            var alg = root.GetProperty("alg").GetString();
            if (!Base64Url.IsExact(root.GetProperty("iv").GetString(), 12))
            {
                return false;
            }

            var ct = Base64Url.Decode(root.GetProperty("ct").GetString() ?? "");
            if (ct.Length != 48)
            {
                return false;
            }

            if (kind == "password")
            {
                return alg == "PBKDF2-SHA512-AES-256-GCM"
                    && root.GetProperty("iterations").GetInt32() == PasswordIterations
                    && Base64Url.IsExact(root.GetProperty("salt").GetString(), 16);
            }

            return kind == "passkey" && alg == "PRF-AES-256-GCM";
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or FormatException or InvalidOperationException)
        {
            return false;
        }
    }
}
